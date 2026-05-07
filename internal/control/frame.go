// Package control implements the daemon side of the dmg.control/v1
// WebSocket protocol. The package is split across:
//
//   - frame.go      - wire-format types (Hello / Command / Result)
//   - handler.go    - the Handler contract every feature implements
//   - registry.go   - in-process command dispatcher (one slot, idempotency)
//   - idempotency.go - LRU+TTL replay cache
//
// The transport (dial, reconnect, frame loop) lives in
// internal/control/wsclient. Feature handlers (hooks install/uninstall,
// future toggles) live in internal/control/handlers.
//
// Schema and behavior MUST track .plans/control-plane-api-contract.md.
// Anything in the doc that says "the daemon" is implemented in this
// directory; anything that says "the backend" is implemented elsewhere.
package control

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the schema string the daemon writes in the hello
// frame and the value the backend MUST echo on every command frame.
// Bumps coordinate with the backend; do not bump in isolation.
const SchemaVersion = "dmg.control/v1"

// FrameType is the discriminator on every JSON frame's `type` field.
type FrameType string

const (
	FrameHello   FrameType = "hello"
	FrameCommand FrameType = "command"
	FrameResult  FrameType = "result"
)

// Hello is the first frame the daemon emits after the WebSocket
// upgrade. The backend MUST receive it within 2 seconds or close the
// connection (close code 1002). Field shapes match the API contract.
type Hello struct {
	Type         FrameType `json:"type"`
	Schema       string    `json:"schema"`
	DeviceID     string    `json:"device_id"`
	CustomerID   string    `json:"customer_id"`
	AgentVersion string    `json:"agent_version"`
	Platform     string    `json:"platform"`
	Capabilities []string  `json:"capabilities"`
}

// Command is an incoming server-issued command frame. Args is left raw
// so per-handler parsing keeps the registry oblivious to feature schemas.
type Command struct {
	Type       FrameType       `json:"type"`
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Args       json.RawMessage `json:"args,omitempty"`
	DeadlineMS int             `json:"deadline_ms,omitempty"`
}

// Deadline returns the per-command timeout. The contract specifies a
// 30s default and a 120s ceiling; out-of-range values are clamped here
// rather than in the WS reader so a malformed backend can't bypass the
// cap by going through some other code path.
func (c Command) Deadline() time.Duration {
	const (
		defaultMS = 30000
		minMS     = 1000
		maxMS     = 120000
	)
	ms := c.DeadlineMS
	if ms <= 0 {
		ms = defaultMS
	}
	if ms < minMS {
		ms = minMS
	}
	if ms > maxMS {
		ms = maxMS
	}
	return time.Duration(ms) * time.Millisecond
}

// Result is the daemon's reply to a Command. ID, StartedAt, and
// FinishedAt are mandatory; exactly one of Data or Error is meaningful
// depending on Ok.
type Result struct {
	Type       FrameType  `json:"type"`
	ID         string     `json:"id"`
	Ok         bool       `json:"ok"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at"`
	Data       any        `json:"data"`
	Error      *ErrorBody `json:"error"`
}

// ErrorBody is the typed payload of a failed Result.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// successResult builds an ok=true Result with Data populated. Used by
// the registry once the handler returns; other call sites should not
// construct Result directly.
func successResult(id string, started, finished time.Time, data any) Result {
	return Result{
		Type:       FrameResult,
		ID:         id,
		Ok:         true,
		StartedAt:  started,
		FinishedAt: finished,
		Data:       data,
		Error:      nil,
	}
}

// failureResult builds an ok=false Result with Error populated.
func failureResult(id string, started, finished time.Time, code, message string) Result {
	return Result{
		Type:       FrameResult,
		ID:         id,
		Ok:         false,
		StartedAt:  started,
		FinishedAt: finished,
		Data:       nil,
		Error:      &ErrorBody{Code: code, Message: message},
	}
}
