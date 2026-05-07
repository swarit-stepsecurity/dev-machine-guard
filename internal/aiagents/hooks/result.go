// Package hooks owns install/uninstall orchestration for the AI coding
// agent hooks domain. Both the user-facing CLI handlers
// (internal/aiagents/cli) and the WebSocket control plane
// (internal/control/handlers) call into this package; everything that's
// not strictly presentation lives here.
//
// Functions return typed `[]AgentResult` plus a domain-level error.
// Callers can map domain failures onto CLI exit codes or wire-protocol
// error codes via errors.As against *Error without re-parsing English
// error strings.
package hooks

import (
	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
)

// AgentStatus is the per-agent outcome captured in AgentResult.Status.
type AgentStatus string

const (
	// StatusOK means the adapter ran successfully (install succeeded or
	// uninstall removed entries / was a clean no-op).
	StatusOK AgentStatus = "ok"

	// StatusSkipped means the adapter was not run because the agent's
	// CLI binary was not on $PATH at the time of detection. Only set on
	// the default fan-out path; explicit `--agent <name>` never produces
	// skipped (the user opted in unconditionally).
	StatusSkipped AgentStatus = "skipped"

	// StatusError means the adapter's Install/Uninstall returned an
	// error. The Error field carries the per-adapter message.
	StatusError AgentStatus = "error"
)

// AgentResult is the per-agent outcome of one Install or Uninstall call.
//
// Exactly one of Install / Uninstall is populated, depending on which
// orchestrator function returned the result. Status="skipped" or "error"
// always carries nil Install/Uninstall.
//
// Wire format: this struct's JSON tags ARE the API contract for
// `result.data` in dmg.control/v1. Renaming a field is a breaking
// change.
type AgentResult struct {
	Agent     string                   `json:"agent"`
	Status    AgentStatus              `json:"status"`
	Error     string                   `json:"error,omitempty"`
	Install   *adapter.InstallResult   `json:"install,omitempty"`
	Uninstall *adapter.UninstallResult `json:"uninstall,omitempty"`
	Notes     []string                 `json:"notes,omitempty"`
}
