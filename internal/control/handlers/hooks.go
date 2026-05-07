// Package handlers wires feature-specific control-plane handlers onto
// the registry. One file per feature so adding a new on-demand
// capability is a single Register() call in the daemon plus the
// handler file here.
//
// The contract these handlers honor: NEVER spawn a subprocess. Every
// handler calls into the relevant domain package (aiagents/hooks,
// future internal/config writes for toggles, etc.) the same way an
// HTTP handler calls a service function. Captured stdout/stderr,
// exit-code aggregation, and re-entry into our own binary are out of
// scope.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/aiagents/hooks"
	"github.com/step-security/dev-machine-guard/internal/control"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// CmdHooksInstall is the command name registered for `hooks.install`.
const CmdHooksInstall = "hooks.install"

// CmdHooksUninstall is the command name registered for `hooks.uninstall`.
const CmdHooksUninstall = "hooks.uninstall"

// hooksArgs is the args shape both handlers accept. Field order /
// json tag MUST match the API contract (.plans/control-plane-api-contract.md).
type hooksArgs struct {
	Agent string `json:"agent,omitempty"`
}

// HooksInstall is the control-plane handler for `hooks.install`.
// Constructed once at daemon startup; the registry shares it across
// every invocation. The executor is the daemon's executor.NewReal()
// so the handler sees the same OS view as periodic telemetry does.
type HooksInstall struct {
	exec executor.Executor
}

// NewHooksInstall returns the install handler. exec MUST be the same
// process-wide executor the rest of the daemon uses; we don't accept
// nil — a misconfigured registry would silently no-op every call.
func NewHooksInstall(exec executor.Executor) *HooksInstall {
	if exec == nil {
		panic("control/handlers: NewHooksInstall requires a non-nil executor")
	}
	return &HooksInstall{exec: exec}
}

// Name satisfies control.Handler.
func (h *HooksInstall) Name() string { return CmdHooksInstall }

// Execute parses args, calls hooks.Install, and returns the typed
// []hooks.AgentResult. Errors from the orchestrator are mapped to
// wire-format codes via mapHooksError so the registry surfaces the
// right `error.code` to the backend.
func (h *HooksInstall) Execute(ctx context.Context, args json.RawMessage) (any, error) {
	var p hooksArgs
	if err := unmarshalArgs(args, &p); err != nil {
		return nil, err
	}
	results, herr := hooks.Install(ctx, h.exec, p.Agent)
	if herr != nil {
		return nil, mapHooksError(herr, "install")
	}
	return results, nil
}

// HooksUninstall is the control-plane handler for `hooks.uninstall`.
type HooksUninstall struct {
	exec executor.Executor
}

// NewHooksUninstall returns the uninstall handler. See NewHooksInstall.
func NewHooksUninstall(exec executor.Executor) *HooksUninstall {
	if exec == nil {
		panic("control/handlers: NewHooksUninstall requires a non-nil executor")
	}
	return &HooksUninstall{exec: exec}
}

// Name satisfies control.Handler.
func (h *HooksUninstall) Name() string { return CmdHooksUninstall }

// Execute parses args, calls hooks.Uninstall, and returns the typed
// []hooks.AgentResult.
func (h *HooksUninstall) Execute(ctx context.Context, args json.RawMessage) (any, error) {
	var p hooksArgs
	if err := unmarshalArgs(args, &p); err != nil {
		return nil, err
	}
	results, herr := hooks.Uninstall(ctx, h.exec, p.Agent)
	if herr != nil {
		return nil, mapHooksError(herr, "uninstall")
	}
	return results, nil
}

// unmarshalArgs decodes args into v. Empty args ("" or null) is
// permitted — handlers default to "every detected agent" — but a
// non-empty value that fails to parse becomes a CodeBadArgs.
func unmarshalArgs(args json.RawMessage, v any) error {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	if err := json.Unmarshal(args, v); err != nil {
		return control.WrapHandlerError(control.CodeBadArgs,
			fmt.Sprintf("decode args: %v", err), err)
	}
	return nil
}

// mapHooksError translates a *hooks.Error into a control.HandlerError
// whose Code is the wire-format string the API contract specifies.
// verb is "install" or "uninstall" — used only to disambiguate
// adapter-failed codes in case the upstream code drift between
// install and uninstall.
func mapHooksError(herr *hooks.Error, verb string) error {
	var code string
	switch herr.Code {
	case hooks.CodeEnterpriseConfigMissing:
		code = string(hooks.CodeEnterpriseConfigMissing)
	case hooks.CodeSelfPathFailed:
		code = string(hooks.CodeSelfPathFailed)
	case hooks.CodeTargetUserUnresolved:
		code = string(hooks.CodeTargetUserUnresolved)
	case hooks.CodeUnsupportedAgent:
		// Per API contract, unsupported agent is bad_args from the
		// caller's perspective — the request was malformed.
		code = control.CodeBadArgs
	case hooks.CodeAdapterInstallFailed, hooks.CodeAdapterUninstallFailed:
		code = string(herr.Code)
	default:
		code = control.CodeInternal
	}
	// Preserve the underlying *hooks.Error for callers (and tests) that
	// want to errors.As back to it.
	_ = verb // reserved for future per-verb branching if codes diverge
	return wrapWithCause(code, herr.Error(), herr)
}

// wrapWithCause is a thin adapter around control.WrapHandlerError that
// guarantees we never silently drop the original *hooks.Error.
func wrapWithCause(code, msg string, cause error) error {
	if cause == nil {
		return control.NewHandlerError(code, msg)
	}
	return control.WrapHandlerError(code, msg, cause)
}

// errorsAsHooks is a small convenience used by tests to assert that
// the wrapped *hooks.Error survives the trip through control's
// HandlerError. Exported so handlers_test in this package and any
// future cross-package test can share it.
func errorsAsHooks(err error) *hooks.Error {
	var h *hooks.Error
	if errors.As(err, &h) {
		return h
	}
	return nil
}
