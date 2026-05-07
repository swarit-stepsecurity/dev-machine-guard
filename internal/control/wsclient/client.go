// Package wsclient is the daemon-side transport for dmg.control/v1.
//
// Run blocks until ctx is canceled, owning the lifecycle of a single
// outbound WebSocket connection: dial → hello → command/result loop,
// reconnecting with exponential backoff on every disconnect. The reader
// dispatches each command frame through a control.Registry; results
// are written back over the same connection.
//
// Run is the only public surface. Internal pieces — dial helper, frame
// codec, backoff timer — are package-private and tested via Run.
package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/control"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Constants matching the API contract. Keep in lockstep with
// .plans/control-plane-api-contract.md.
const (
	// ReadDeadline bounds idle time on the connection. The contract
	// specifies 75s; the backend sends ping frames every 30s, so 75s
	// gives us ~2.5 missed pings before forcing a reconnect.
	ReadDeadline = 75 * time.Second

	// MaxFrameBytes caps incoming frames at 1 MiB per the contract.
	// coder/websocket enforces this via SetReadLimit.
	MaxFrameBytes = 1 << 20 // 1 MiB

	// HelloTimeout caps how long we'll wait for the upgrade response
	// to arrive. Independent of ReadDeadline so a pathological dial
	// can't hold the daemon forever.
	HelloTimeout = 30 * time.Second

	// Backoff bounds. Exponential with jitter: each attempt doubles
	// the previous wait (capped at backoffMax) and jitters ±25%.
	backoffMin = 1 * time.Second
	backoffMax = 60 * time.Second
)

// Identity carries the device-level fields the daemon stamps onto the
// hello frame. Construct once at daemon startup from internal/device
// + internal/config; the wsclient never re-resolves these.
type Identity struct {
	DeviceID     string
	CustomerID   string
	APIEndpoint  string // e.g. "https://int.api.stepsecurity.io"
	APIKey       string
	AgentVersion string // defaults to buildinfo.Version when empty
	Platform     string // defaults to runtime.GOOS when empty
}

// Config bundles every dependency Run needs. Held as a struct so the
// daemon can build it once and pass through cleanly; tests construct
// minimal variants.
type Config struct {
	Identity Identity
	Registry *control.Registry
	Logger   *progress.Logger

	// HTTPClient overrides the dial-time http.Client. Production
	// leaves this nil (uses http.DefaultClient with no extra config).
	// Tests inject for cookies / TLS / proxy hooks.
	HTTPClient *http.Client
}

// Run owns the WebSocket lifecycle and returns when ctx is canceled.
// The single returned error is always ctx.Err() — every transport
// failure is logged and recovered via reconnect, never surfaced.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Registry == nil {
		return errors.New("wsclient: nil registry")
	}
	if cfg.Logger == nil {
		cfg.Logger = progress.NewLogger(progress.LevelError)
	}
	if cfg.Identity.AgentVersion == "" {
		cfg.Identity.AgentVersion = buildinfo.Version
	}
	if cfg.Identity.Platform == "" {
		cfg.Identity.Platform = runtime.GOOS
	}

	endpoint, err := buildEndpointURL(cfg.Identity)
	if err != nil {
		return fmt.Errorf("wsclient: build endpoint: %w", err)
	}

	delay := backoffMin
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		cfg.Logger.Progress("control: dialing %s", redactQuery(endpoint))
		err := connectAndRun(ctx, endpoint, cfg)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Any non-context error is a transport-level disconnect; log
		// and back off. The error message is already redacted.
		cfg.Logger.Warn("control: connection ended: %v", err)

		// Sleep with jitter, but allow ctx to interrupt the sleep so
		// SIGTERM-driven shutdowns don't wait out the backoff.
		wait := jitter(delay)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		delay = nextBackoff(delay)
	}
}

// connectAndRun dials, sends hello, then runs the read loop until the
// connection drops. Returns nil only on a clean ctx-driven close so
// the caller can distinguish shutdown from a transport failure.
func connectAndRun(parent context.Context, endpoint string, cfg Config) error {
	dialCtx, cancel := context.WithTimeout(parent, HelloTimeout)
	defer cancel()

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+cfg.Identity.APIKey)
	hdr.Set("X-Agent-Version", cfg.Identity.AgentVersion)
	hdr.Set("User-Agent", "dmg/"+cfg.Identity.AgentVersion)

	dialOpts := &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: cfg.HTTPClient,
	}

	conn, _, err := websocket.Dial(dialCtx, endpoint, dialOpts)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()

	conn.SetReadLimit(MaxFrameBytes)

	if err := writeHello(parent, conn, cfg); err != nil {
		// Close with an explicit code so the backend logs the reason.
		_ = conn.Close(websocket.StatusInternalError, "hello write failed")
		return fmt.Errorf("write hello: %w", err)
	}
	cfg.Logger.Progress("control: connected (capabilities=%v)", cfg.Registry.Capabilities())

	if err := readLoop(parent, conn, cfg); err != nil {
		// readLoop already classifies — pass through, possibly nil if
		// parent ctx was canceled during a graceful close.
		return err
	}
	return nil
}

// writeHello marshals and sends the hello frame.
func writeHello(ctx context.Context, conn *websocket.Conn, cfg Config) error {
	hello := control.Hello{
		Type:         control.FrameHello,
		Schema:       control.SchemaVersion,
		DeviceID:     cfg.Identity.DeviceID,
		CustomerID:   cfg.Identity.CustomerID,
		AgentVersion: cfg.Identity.AgentVersion,
		Platform:     cfg.Identity.Platform,
		Capabilities: cfg.Registry.Capabilities(),
	}
	body, err := json.Marshal(hello)
	if err != nil {
		return fmt.Errorf("marshal hello: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, body)
}

// readLoop reads frames in a loop, dispatching each command and
// writing back the result. Loop exits on any read error. Read deadline
// is enforced by reading inside a context with a fresh timeout each
// iteration — coder/websocket has no SetReadDeadline equivalent.
func readLoop(parent context.Context, conn *websocket.Conn, cfg Config) error {
	for {
		readCtx, cancel := context.WithTimeout(parent, ReadDeadline)
		typ, body, err := conn.Read(readCtx)
		cancel()
		if err != nil {
			if parent.Err() != nil {
				_ = conn.Close(websocket.StatusNormalClosure, "shutdown")
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		if typ != websocket.MessageText {
			cfg.Logger.Warn("control: unexpected frame type %v; dropping", typ)
			continue
		}

		// Parse the envelope to discriminate. We only respond to
		// `command` frames; unknown types are logged and dropped.
		var env struct {
			Type control.FrameType `json:"type"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			cfg.Logger.Warn("control: malformed frame, dropping: %v", err)
			continue
		}
		if env.Type != control.FrameCommand {
			cfg.Logger.Debug("control: ignoring %s frame", env.Type)
			continue
		}

		var cmd control.Command
		if err := json.Unmarshal(body, &cmd); err != nil {
			cfg.Logger.Warn("control: malformed command frame, dropping: %v", err)
			continue
		}

		cfg.Logger.Progress("control: command %s id=%s", cmd.Name, cmd.ID)
		res := cfg.Registry.Dispatch(parent, cmd)
		if err := writeResult(parent, conn, res); err != nil {
			// Failure writing back means the connection is unhealthy;
			// surface to caller for reconnect.
			return fmt.Errorf("write result for %s: %w", cmd.ID, err)
		}
	}
}

// writeResult JSON-serializes and writes a result frame.
func writeResult(ctx context.Context, conn *websocket.Conn, res control.Result) error {
	body, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, body)
}

// buildEndpointURL converts the configured https:// API endpoint into
// the wss:// control URL with the device + customer path components.
// http:// becomes ws:// for local testing, but production endpoints
// must be TLS.
func buildEndpointURL(id Identity) (string, error) {
	if id.APIEndpoint == "" {
		return "", errors.New("empty api_endpoint")
	}
	if id.CustomerID == "" || id.DeviceID == "" {
		return "", errors.New("empty customer_id or device_id")
	}
	u, err := url.Parse(strings.TrimRight(id.APIEndpoint, "/"))
	if err != nil {
		return "", fmt.Errorf("parse api_endpoint: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("api_endpoint scheme %q not supported (need http or https)", u.Scheme)
	}
	// Set Path with unescaped values; clear RawPath so url.URL.String()
	// encodes path segments correctly. Pre-escaping (url.PathEscape) and
	// then assigning to Path causes double-encoding because Path is the
	// canonical *unescaped* form.
	u.Path = strings.TrimRight(u.Path, "/") +
		"/v1/" + id.CustomerID +
		"/devices/" + id.DeviceID +
		"/control"
	u.RawPath = ""
	return u.String(), nil
}

// nextBackoff doubles delay up to backoffMax. Plain exponential —
// jitter happens at the call site so this stays trivially testable.
func nextBackoff(prev time.Duration) time.Duration {
	next := prev * 2
	if next > backoffMax {
		return backoffMax
	}
	if next < backoffMin {
		return backoffMin
	}
	return next
}

// jitter applies ±25% randomness to d. Uses math/rand/v2 (no global
// seed needed) — backoff jitter doesn't need crypto-strength entropy.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	jitterRange := float64(d) * 0.25
	delta := (rand.Float64()*2 - 1) * jitterRange
	return d + time.Duration(delta)
}

// redactQuery strips any query string from a URL for logging — keys
// or tokens occasionally leak into endpoint URLs and we never want
// them in journalctl output.
func redactQuery(u string) string {
	if i := strings.Index(u, "?"); i >= 0 {
		return u[:i] + "?[REDACTED]"
	}
	return u
}
