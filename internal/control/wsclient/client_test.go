package wsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/step-security/dev-machine-guard/internal/control"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestValidateEndpoint(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want string
	}{
		{
			name: "wss accepted as-is",
			id: Identity{
				WSEndpoint: "wss://int.websocket-api.stepsecurity.io/v1",
				CustomerID: "step-security",
				DeviceID:   "C02XXX",
			},
			want: "wss://int.websocket-api.stepsecurity.io/v1",
		},
		{
			name: "trailing slash stripped",
			id: Identity{
				WSEndpoint: "wss://ws.example.com/v1/",
				CustomerID: "cust",
				DeviceID:   "dev",
			},
			want: "wss://ws.example.com/v1",
		},
		{
			name: "ws scheme accepted (test/dev)",
			id: Identity{
				WSEndpoint: "ws://localhost:8080",
				CustomerID: "c",
				DeviceID:   "d",
			},
			want: "ws://localhost:8080",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateEndpoint(tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestValidateEndpoint_Errors(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
	}{
		{"empty endpoint", Identity{CustomerID: "c", DeviceID: "d"}},
		{"empty customer", Identity{WSEndpoint: "wss://x.example", DeviceID: "d"}},
		{"empty device", Identity{WSEndpoint: "wss://x.example", CustomerID: "c"}},
		{"unknown scheme", Identity{WSEndpoint: "https://x.example", CustomerID: "c", DeviceID: "d"}},
		{"missing host", Identity{WSEndpoint: "wss://", CustomerID: "c", DeviceID: "d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateEndpoint(tc.id); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNextBackoff(t *testing.T) {
	prev := backoffMin
	for range 20 {
		next := nextBackoff(prev)
		if next < prev && next != backoffMax {
			t.Errorf("backoff regressed: prev=%v next=%v", prev, next)
		}
		if next > backoffMax {
			t.Errorf("backoff exceeded cap: %v > %v", next, backoffMax)
		}
		prev = next
	}
	if prev != backoffMax {
		t.Errorf("expected backoff to converge on cap, got %v", prev)
	}
}

func TestJitterStaysWithin25Percent(t *testing.T) {
	const d = 4 * time.Second
	min := time.Duration(float64(d) * 0.75)
	max := time.Duration(float64(d) * 1.25)
	for range 100 {
		got := jitter(d)
		if got < min || got > max {
			t.Errorf("jitter(%v) = %v, outside [%v, %v]", d, got, min, max)
		}
	}
}

func TestRedactQuery(t *testing.T) {
	cases := map[string]string{
		"https://x.example/path":             "https://x.example/path",
		"https://x.example/path?token=secret": "https://x.example/path?[REDACTED]",
	}
	for in, want := range cases {
		if got := redactQuery(in); got != want {
			t.Errorf("redactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

// echoHandler is the in-memory WS server used by the round-trip test.
// Reads the daemon's hello, then writes a single command, then waits
// for the result back. Captures everything for assertion.
type echoHandler struct {
	mu        sync.Mutex
	hello     control.Hello
	gotResult control.Result
	command   control.Command
	done      chan struct{}
}

func (h *echoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusInternalError, "")

	ctx := r.Context()

	// Read hello.
	_, body, err := c.Read(ctx)
	if err != nil {
		return
	}
	var hello control.Hello
	if err := json.Unmarshal(body, &hello); err == nil {
		h.mu.Lock()
		h.hello = hello
		h.mu.Unlock()
	}

	// Write a command.
	cmdBody, _ := json.Marshal(h.command)
	if err := c.Write(ctx, websocket.MessageText, cmdBody); err != nil {
		return
	}

	// Read the result.
	_, body, err = c.Read(ctx)
	if err != nil {
		return
	}
	var result control.Result
	_ = json.Unmarshal(body, &result)
	h.mu.Lock()
	h.gotResult = result
	h.mu.Unlock()

	close(h.done)
	c.Close(websocket.StatusNormalClosure, "done")
}

// stubHandler — same shape as the registry tests'.
type stubHandler struct {
	name string
	fn   func(ctx context.Context, args json.RawMessage) (any, error)
}

func (s *stubHandler) Name() string { return s.name }
func (s *stubHandler) Execute(ctx context.Context, args json.RawMessage) (any, error) {
	if s.fn != nil {
		return s.fn(ctx, args)
	}
	return "ok", nil
}

// TestRun_RoundTrip exercises the full client lifecycle against an
// in-memory WS server: dial → hello → command → result. Any of those
// breaking would have downstream consequences when the daemon talks
// to the real backend.
func TestRun_RoundTrip(t *testing.T) {
	h := &echoHandler{
		command: control.Command{
			Type: control.FrameCommand,
			ID:   "cmd-1",
			Name: "echo",
			Args: json.RawMessage(`"hi"`),
		},
		done: make(chan struct{}),
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	reg := control.NewRegistry(nil)
	reg.Register(&stubHandler{name: "echo", fn: func(_ context.Context, args json.RawMessage) (any, error) {
		return string(args), nil
	}})

	cfg := Config{
		Identity: Identity{
			WSEndpoint:   httpToWS(ts.URL),
			CustomerID:   "cust",
			DeviceID:     "dev",
			APIKey:       "k",
			AgentVersion: "test",
			Platform:     "linux",
		},
		Registry: reg,
		Logger:   progress.NewLogger(progress.LevelError),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runCh := make(chan error, 1)
	go func() { runCh <- Run(ctx, cfg) }()

	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not complete round-trip in time")
	}

	cancel()
	<-runCh

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.hello.Schema != control.SchemaVersion {
		t.Errorf("hello.Schema=%q", h.hello.Schema)
	}
	if h.hello.DeviceID != "dev" || h.hello.CustomerID != "cust" {
		t.Errorf("hello identity wrong: %+v", h.hello)
	}
	if len(h.hello.Capabilities) != 1 || h.hello.Capabilities[0] != "echo" {
		t.Errorf("hello capabilities = %v", h.hello.Capabilities)
	}

	if !h.gotResult.Ok {
		t.Errorf("result not ok: %+v", h.gotResult)
	}
	if h.gotResult.ID != "cmd-1" {
		t.Errorf("result.ID=%q", h.gotResult.ID)
	}
	if data := h.gotResult.Data; data != `"hi"` {
		t.Errorf("result.Data=%v", data)
	}
}

// TestRun_AuthHeaderSent confirms the upgrade carries the Bearer
// header — without that, the backend has no way to authenticate the
// daemon.
func TestRun_AuthHeaderSent(t *testing.T) {
	gotAuth := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth <- r.Header.Get("Authorization")
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		// Read hello so the daemon proceeds, then close.
		_, _, _ = c.Read(r.Context())
		c.Close(websocket.StatusNormalClosure, "done")
	}))
	defer srv.Close()

	reg := control.NewRegistry(nil)
	cfg := Config{
		Identity: Identity{
			WSEndpoint:   httpToWS(srv.URL),
			CustomerID:   "cust-1",
			DeviceID:     "dev-X",
			APIKey:       "shh-secret",
			AgentVersion: "test",
			Platform:     "linux",
		},
		Registry: reg,
		Logger:   progress.NewLogger(progress.LevelError),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go Run(ctx, cfg)

	select {
	case got := <-gotAuth:
		if !strings.HasPrefix(got, "Bearer ") || !strings.HasSuffix(got, "shh-secret") {
			t.Errorf("auth header = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received upgrade")
	}
}

// TestRun_IdentityHeadersSent confirms the upgrade carries the
// customer/device identity headers — without these, the API Gateway
// $connect handler can't route the connection to the right device row.
func TestRun_IdentityHeadersSent(t *testing.T) {
	type captured struct {
		customer, device, version, platform string
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- captured{
			customer: r.Header.Get("X-Stepsecurity-Customer-Name"),
			device:   r.Header.Get("X-Stepsecurity-Device-Id"),
			version:  r.Header.Get("X-Stepsecurity-Agent-Version"),
			platform: r.Header.Get("X-Stepsecurity-Platform"),
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_, _, _ = c.Read(r.Context())
		c.Close(websocket.StatusNormalClosure, "done")
	}))
	defer srv.Close()

	reg := control.NewRegistry(nil)
	cfg := Config{
		Identity: Identity{
			WSEndpoint:   httpToWS(srv.URL),
			CustomerID:   "step-security",
			DeviceID:     "C02XXX",
			APIKey:       "k",
			AgentVersion: "9.9.9",
			Platform:     "linux",
		},
		Registry: reg,
		Logger:   progress.NewLogger(progress.LevelError),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go Run(ctx, cfg)

	select {
	case h := <-got:
		if h.customer != "step-security" {
			t.Errorf("customer header = %q", h.customer)
		}
		if h.device != "C02XXX" {
			t.Errorf("device header = %q", h.device)
		}
		if h.version != "9.9.9" {
			t.Errorf("version header = %q", h.version)
		}
		if h.platform != "linux" {
			t.Errorf("platform header = %q", h.platform)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received upgrade")
	}
}

// httpToWS rewrites an httptest.NewServer URL ("http://...") to the
// "ws://" scheme our validator now requires. httptest gives back HTTP;
// the protocol upgrade still works on ws://, but our config layer no
// longer accepts http:// to keep production callers honest.
func httpToWS(httpURL string) string {
	if strings.HasPrefix(httpURL, "https://") {
		return "wss://" + strings.TrimPrefix(httpURL, "https://")
	}
	if strings.HasPrefix(httpURL, "http://") {
		return "ws://" + strings.TrimPrefix(httpURL, "http://")
	}
	return httpURL
}
