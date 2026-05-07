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
	// ReadDeadline bounds idle time on the connection. AWS API Gateway
	// WebSocket APIs do NOT send ping frames on idle connections (and
	// also enforce a 10-minute idle timeout that closes them silently).
	// We therefore drive keep-alive from the client side: send a
	// WS-level ping every PingInterval and use ReadDeadline as the
	// outer cap, leaving headroom for one missed pong.
	ReadDeadline = 75 * time.Second

	// PingInterval is how often we send a WS-level ping. 30s is well
	// inside API Gateway's 10-minute idle timeout AND inside our own
	// ReadDeadline above. coder/websocket's Ping waits for the pong,
	// so a successful Ping return refreshes our read activity.
	PingInterval = 30 * time.Second

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
// upgrade request and the hello frame. Construct once at daemon
// startup from internal/device + internal/config; the wsclient never
// re-resolves these.
//
// WSEndpoint is the absolute wss:// URL the daemon dials, taken
// verbatim from `~/.stepsecurity/config.json`'s `ws_endpoint` field
// (e.g. "wss://int.websocket-api.stepsecurity.io/v1"). API Gateway
// WebSocket APIs do not route on URL path beyond the stage; the
// customer + device identity is carried in custom headers and
// validated by the backend's $connect handler.
type Identity struct {
	DeviceID     string
	CustomerID   string
	WSEndpoint   string
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

	endpoint, err := validateEndpoint(cfg.Identity)
	if err != nil {
		return fmt.Errorf("wsclient: %w", err)
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

	// Custom headers carry the customer + device identity — API Gateway
	// WS APIs don't route on URL paths, so identity is at the header
	// layer. The backend's $connect handler validates Authorization
	// against the customer's TenantAPIKey, then registers the
	// connection_id under (customer_name, device_id).
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+cfg.Identity.APIKey)
	hdr.Set("X-Stepsecurity-Customer-Name", cfg.Identity.CustomerID)
	hdr.Set("X-Stepsecurity-Device-Id", cfg.Identity.DeviceID)
	hdr.Set("X-Stepsecurity-Agent-Version", cfg.Identity.AgentVersion)
	hdr.Set("X-Stepsecurity-Platform", cfg.Identity.Platform)
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

	// Start a sibling goroutine that keeps the connection alive by
	// sending WS-level pings on PingInterval. AWS API Gateway WS
	// doesn't ping us, and silent idle timeouts (10 min) plus our own
	// ReadDeadline (75s) would otherwise force a reconnect every few
	// minutes — wasteful in Lambda invocations and DDB churn.
	//
	// connCtx scopes the pinger to this single connection: when
	// readLoop returns and we hit the cancel below, the pinger exits.
	connCtx, cancelConn := context.WithCancel(parent)
	defer cancelConn()
	go runPinger(connCtx, conn, cfg.Logger)

	if err := readLoop(parent, conn, cfg); err != nil {
		// readLoop already classifies — pass through, possibly nil if
		// parent ctx was canceled during a graceful close.
		return err
	}
	return nil
}

// runPinger fires a WS-level ping every PingInterval until ctx is
// canceled or the ping fails. coder/websocket's Conn.Ping is safe to
// call concurrently with Read/Write.
//
// On ping failure (timeout or transport error) the pinger closes the
// connection. That unblocks the read loop with a closed-connection
// error, which triggers reconnect. Without this, the read loop would
// stay parked forever on a half-open socket — pings happen at the
// protocol layer and don't surface to Read.
func runPinger(ctx context.Context, conn *websocket.Conn, log *progress.Logger) {
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				log.Debug("control: ping failed, closing connection: %v", err)
				_ = conn.Close(websocket.StatusGoingAway, "ping failed")
				return
			}
		}
	}
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
// writing back the result. Loop exits on any read error.
//
// No per-iteration read deadline: WS-level pings/pongs are handled by
// coder/websocket internally and never surface to Read, so a deadline
// here would fire whenever the backend has nothing to push (the
// common case). Liveness is enforced by the pinger goroutine, which
// closes the connection on ping failure — Read then returns the
// closed-connection error and the loop exits naturally.
func readLoop(parent context.Context, conn *websocket.Conn, cfg Config) error {
	for {
		typ, body, err := conn.Read(parent)
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

// validateEndpoint sanity-checks the absolute wss:// URL the caller
// configured. The URL is taken verbatim — no path templating, no
// scheme rewriting — because API Gateway WebSocket APIs route on
// stage only, with all customer/device identity carried in headers.
// Returns the trimmed URL for dial, or an error when required fields
// are missing.
func validateEndpoint(id Identity) (string, error) {
	if id.WSEndpoint == "" {
		return "", errors.New("empty ws_endpoint")
	}
	if id.CustomerID == "" || id.DeviceID == "" {
		return "", errors.New("empty customer_id or device_id")
	}
	endpoint := strings.TrimRight(id.WSEndpoint, "/")
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse ws_endpoint: %w", err)
	}
	switch u.Scheme {
	case "wss", "ws":
		// Both accepted; "ws" is for local dev/testing only — production
		// loaders write "wss". coder/websocket handles either.
	default:
		return "", fmt.Errorf("ws_endpoint scheme %q not supported (need ws or wss)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("ws_endpoint missing host: %q", endpoint)
	}
	return endpoint, nil
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
