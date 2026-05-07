package control

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Registry routes Command frames to Handlers and serializes their
// execution. One registry per daemon process; goroutine-safe.
//
// Lifecycle: Register handlers at startup, then call Dispatch from the
// WS reader loop. Capabilities() snapshots the registered names for
// the hello frame.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
	cache    *ResultCache
	busy     chan struct{} // size 1 — single-slot executor
	now      func() time.Time
}

// NewRegistry returns a Registry backed by a fresh ResultCache. Pass
// nil for cache to use defaults.
func NewRegistry(cache *ResultCache) *Registry {
	if cache == nil {
		cache = NewResultCache(0, 0)
	}
	return &Registry{
		handlers: make(map[string]Handler),
		cache:    cache,
		busy:     make(chan struct{}, 1),
		now:      time.Now,
	}
}

// Register adds h to the registry. Subsequent Register calls with the
// same Name() overwrite the previous handler — useful for tests but
// production code should treat re-registration as a programmer error.
func (r *Registry) Register(h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[h.Name()] = h
}

// Capabilities returns the registered handler names in sorted order.
// The order matters because it appears in the hello frame, which the
// backend may diff against an expected set.
func (r *Registry) Capabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Dispatch resolves the handler for cmd, runs it under a per-command
// deadline, and returns a Result ready for serialization onto the wire.
// Always returns a Result — never an error. The wire-format error code
// is encoded inside Result.Error.
//
// Routing rules (in order):
//   - Unknown handler                 → Result{Error: unknown_command}
//   - Command id replay               → cached Result re-emitted
//   - Same id already in flight       → Result{Error: in_progress}
//   - Different command in flight     → Result{Error: busy}
//   - Otherwise: run handler under the command deadline and cache.
//
// parent is the daemon's overall context; canceling it propagates to
// the in-flight handler.
func (r *Registry) Dispatch(parent context.Context, cmd Command) Result {
	started := r.now()

	cached, outcome, publish := r.cache.GetOrReserve(cmd.ID)
	switch outcome {
	case OutcomeReplay:
		return cached
	case OutcomeInFlight:
		return failureResult(cmd.ID, started, r.now(), CodeInProgress,
			"a command with this id is already running")
	}

	// OutcomeReserved — we own this id. Make sure publish runs even on
	// panic so the cache doesn't keep the slot in stateInFlight forever.
	var resp Result
	defer func() { publish(resp) }()

	r.mu.RLock()
	h, ok := r.handlers[cmd.Name]
	r.mu.RUnlock()
	if !ok {
		resp = failureResult(cmd.ID, started, r.now(), CodeUnknownCommand,
			fmt.Sprintf("no handler registered for %q", cmd.Name))
		return resp
	}

	// Single-slot acquire. Non-blocking: if another command is in
	// flight we reply busy immediately. The backend retries after the
	// command's own deadline_ms, so blocking here would just stall the
	// reader loop and risk piling up.
	select {
	case r.busy <- struct{}{}:
		defer func() { <-r.busy }()
	default:
		resp = failureResult(cmd.ID, started, r.now(), CodeBusy,
			"another command is currently executing")
		return resp
	}

	ctx, cancel := context.WithTimeout(parent, cmd.Deadline())
	defer cancel()

	data, err := executeRecover(ctx, h, cmd.Args)
	finished := r.now()
	if err != nil {
		resp = failureResult(cmd.ID, started, finished, classifyError(err), err.Error())
		return resp
	}
	resp = successResult(cmd.ID, started, finished, data)
	return resp
}

// executeRecover runs h.Execute under a panic guard. A panic becomes a
// CodePanic HandlerError so the wire format stays well-formed and the
// daemon's reader loop continues.
func executeRecover(ctx context.Context, h Handler, args []byte) (data any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewHandlerError(CodePanic, fmt.Sprintf("panic in handler %s: %v", h.Name(), r))
		}
	}()
	// Cast back to json.RawMessage at the boundary so handler signatures
	// stay clear. []byte and json.RawMessage are layout-identical.
	return h.Execute(ctx, args)
}

// classifyError maps a handler's returned error onto a wire-format
// code. *HandlerError carries its own; everything else collapses to
// CodeInternal.
func classifyError(err error) string {
	var he *HandlerError
	if errors.As(err, &he) {
		return he.Code
	}
	return CodeInternal
}
