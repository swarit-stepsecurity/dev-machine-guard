package control

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// stubHandler is a parameterizable Handler used across registry tests.
// fn is the body; if nil, Execute returns ("ok", nil).
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

func newCmd(id, name string) Command {
	return Command{Type: FrameCommand, ID: id, Name: name}
}

func TestRegistry_DispatchSuccess(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "echo", fn: func(_ context.Context, args json.RawMessage) (any, error) {
		return string(args), nil
	}})

	cmd := newCmd("1", "echo")
	cmd.Args = json.RawMessage(`"hello"`)

	res := r.Dispatch(context.Background(), cmd)
	if !res.Ok {
		t.Fatalf("ok=false; error=%+v", res.Error)
	}
	if res.Data.(string) != `"hello"` {
		t.Errorf("Data=%v", res.Data)
	}
	if res.ID != "1" {
		t.Errorf("ID=%q", res.ID)
	}
	if res.Type != FrameResult {
		t.Errorf("Type=%q", res.Type)
	}
}

func TestRegistry_UnknownCommand(t *testing.T) {
	r := NewRegistry(nil)
	res := r.Dispatch(context.Background(), newCmd("1", "no.such"))
	if res.Ok || res.Error == nil || res.Error.Code != CodeUnknownCommand {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestRegistry_HandlerErrorClassified(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "bad", fn: func(context.Context, json.RawMessage) (any, error) {
		return nil, NewHandlerError(CodeBadArgs, "bogus")
	}})

	res := r.Dispatch(context.Background(), newCmd("1", "bad"))
	if res.Ok || res.Error == nil || res.Error.Code != CodeBadArgs {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestRegistry_PlainErrorBecomesInternal(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "bad", fn: func(context.Context, json.RawMessage) (any, error) {
		return nil, errors.New("plain")
	}})

	res := r.Dispatch(context.Background(), newCmd("1", "bad"))
	if res.Ok || res.Error == nil || res.Error.Code != CodeInternal {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestRegistry_PanicBecomesPanicCode(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "boom", fn: func(context.Context, json.RawMessage) (any, error) {
		panic("kaboom")
	}})

	res := r.Dispatch(context.Background(), newCmd("1", "boom"))
	if res.Ok || res.Error == nil || res.Error.Code != CodePanic {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestRegistry_BusyOnConcurrentDifferentIDs(t *testing.T) {
	r := NewRegistry(nil)
	gate := make(chan struct{})
	release := make(chan struct{})
	r.Register(&stubHandler{name: "slow", fn: func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(gate)
		<-release
		return "done", nil
	}})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.Dispatch(context.Background(), newCmd("first", "slow"))
	}()
	<-gate // first command is now in flight

	// Second different-id command must get busy immediately.
	res := r.Dispatch(context.Background(), newCmd("second", "slow"))
	if res.Ok || res.Error == nil || res.Error.Code != CodeBusy {
		t.Errorf("expected busy, got: %+v", res)
	}

	close(release)
	wg.Wait()
}

func TestRegistry_InProgressOnSameID(t *testing.T) {
	r := NewRegistry(nil)
	gate := make(chan struct{})
	release := make(chan struct{})
	r.Register(&stubHandler{name: "slow", fn: func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(gate)
		<-release
		return "done", nil
	}})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.Dispatch(context.Background(), newCmd("same", "slow"))
	}()
	<-gate

	// Same-id second call must be in_progress, not busy.
	res := r.Dispatch(context.Background(), newCmd("same", "slow"))
	if res.Ok || res.Error == nil || res.Error.Code != CodeInProgress {
		t.Errorf("expected in_progress, got: %+v", res)
	}

	close(release)
	wg.Wait()
}

func TestRegistry_ReplaysCachedResult(t *testing.T) {
	r := NewRegistry(nil)
	calls := 0
	r.Register(&stubHandler{name: "count", fn: func(context.Context, json.RawMessage) (any, error) {
		calls++
		return calls, nil
	}})

	res1 := r.Dispatch(context.Background(), newCmd("X", "count"))
	res2 := r.Dispatch(context.Background(), newCmd("X", "count"))

	if calls != 1 {
		t.Errorf("handler ran %d times, want 1 (replay should re-emit cache)", calls)
	}
	if res1.Data != res2.Data {
		t.Errorf("replay mismatch: %v vs %v", res1.Data, res2.Data)
	}
}

func TestRegistry_DeadlineHonored(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "block", fn: func(ctx context.Context, _ json.RawMessage) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})

	cmd := newCmd("1", "block")
	cmd.DeadlineMS = 1000 // bumped above the 1s floor; we actually wait <50ms

	start := time.Now()
	// Use a parent context with our own short deadline so this test
	// stays fast — registry's deadline is the inner cap, but the
	// parent cancel still propagates.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := r.Dispatch(ctx, cmd)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("dispatch took %v, expected <500ms (parent ctx must propagate)", elapsed)
	}
	// The handler returned ctx.Err() (context.DeadlineExceeded), which
	// is a plain error → CodeInternal.
	if res.Ok || res.Error == nil || res.Error.Code != CodeInternal {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestRegistry_CapabilitiesSorted(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&stubHandler{name: "z.zebra"})
	r.Register(&stubHandler{name: "a.apple"})
	r.Register(&stubHandler{name: "m.melon"})

	got := r.Capabilities()
	want := []string{"a.apple", "m.melon", "z.zebra"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d (got=%v)", len(got), len(want), got)
	}
	for i, n := range want {
		if got[i] != n {
			t.Errorf("[%d]=%q, want %q", i, got[i], n)
		}
	}
}
