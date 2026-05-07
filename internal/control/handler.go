package control

import (
	"context"
	"encoding/json"
)

// Error catalog — string values match the API contract's "Error
// catalog" table verbatim. Adapters / feature handlers reuse these
// codes via NewError when they want to map their domain errors onto
// well-known wire codes; one-off codes are fine too, but the catalog
// names should stay in lockstep with the contract.
const (
	CodeUnknownCommand = "unknown_command"
	CodeBadArgs        = "bad_args"
	CodeBusy           = "busy"
	CodeInProgress     = "in_progress"
	CodePanic          = "panic"
	CodeInternal       = "internal"
)

// Handler is the contract every feature implements to plug into the
// control plane. One Handler per command name. Implementations MUST be
// safe to call concurrently — even though the registry's single-slot
// executor serializes invocations today, that's a registry policy, not
// a Handler invariant.
//
// The Execute return value's `any` is JSON-marshaled into the result
// frame's `data` field. Returning a typed struct (with json tags) is
// preferred over `map[string]any` so the wire shape is documented in
// the handler's source.
type Handler interface {
	// Name is the command name the registry routes by. Must match
	// the daemon's hello capabilities list.
	Name() string

	// Execute runs the command. ctx is bounded by the per-command
	// deadline (Command.Deadline()) and by the daemon's overall
	// shutdown context. args is the raw `args` field of the command
	// frame; handlers are responsible for unmarshaling and validating.
	//
	// A returned error is mapped to a failure Result by the
	// registry. To control the wire-format error code, return a
	// *HandlerError; any other error type maps to CodeInternal.
	Execute(ctx context.Context, args json.RawMessage) (any, error)
}

// HandlerError lets a Handler attach a wire-format error code to its
// failure. Plain `error` values map to CodeInternal — use HandlerError
// when the failure is a known classification (bad_args, etc.).
type HandlerError struct {
	Code    string
	Message string
	cause   error
}

// Error returns "<code>: <message>" or just "<code>" when the message
// is empty.
func (e *HandlerError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Unwrap exposes the wrapped cause for errors.As traversal.
func (e *HandlerError) Unwrap() error { return e.cause }

// NewHandlerError constructs a HandlerError with no cause. Used when
// the failure originates inside the handler.
func NewHandlerError(code, message string) *HandlerError {
	return &HandlerError{Code: code, Message: message}
}

// WrapHandlerError wraps cause with code/message, preserving the
// original error for errors.As traversal.
func WrapHandlerError(code, message string, cause error) *HandlerError {
	if cause != nil && message == "" {
		message = cause.Error()
	}
	return &HandlerError{Code: code, Message: message, cause: cause}
}
