package hooks

import "fmt"

// ErrorCode classifies orchestration failures at a level both the CLI
// presenter and the control-plane wire format can map directly. The
// string values ARE the wire format codes (see
// .plans/control-plane-api-contract.md "Error catalog"); changing them
// is a breaking change.
type ErrorCode string

const (
	// CodeEnterpriseConfigMissing — Snapshot returned not-ok. Install
	// only; uninstall must work post-credential-revocation.
	CodeEnterpriseConfigMissing ErrorCode = "enterprise_config_missing"

	// CodeSelfPathFailed — could not resolve the absolute path of the
	// running binary; adapters need it to write hook commands.
	CodeSelfPathFailed ErrorCode = "selfpath_failed"

	// CodeTargetUserUnresolved — running as root with no console user.
	// Caller should treat as a no-op success rather than a hard failure.
	CodeTargetUserUnresolved ErrorCode = "target_user_unresolved"

	// CodeUnsupportedAgent — explicit agent name does not match any
	// registered adapter.
	CodeUnsupportedAgent ErrorCode = "unsupported_agent"

	// CodeAdapterInstallFailed — at least one adapter's Install
	// returned an error. Look at AgentResult.Error per-agent for
	// per-adapter detail.
	CodeAdapterInstallFailed ErrorCode = "adapter_install_failed"

	// CodeAdapterUninstallFailed — same, for Uninstall.
	CodeAdapterUninstallFailed ErrorCode = "adapter_uninstall_failed"

	// CodeInternal — unexpected error not in the catalog above. Treat
	// as retryable on the wire.
	CodeInternal ErrorCode = "internal"
)

// Error is the typed error returned by Install / Uninstall. Callers
// extract via errors.As and switch on Code; never parse Message.
type Error struct {
	Code    ErrorCode
	Message string
	cause   error
}

// Error renders code and message; format is for logs, not the wire.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

// Unwrap exposes the wrapped cause for errors.Is / errors.As traversal.
func (e *Error) Unwrap() error { return e.cause }

// newError constructs an Error with no underlying cause. Internal use only.
func newError(code ErrorCode, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// wrapError constructs an Error wrapping cause. Internal use only.
func wrapError(code ErrorCode, msg string, cause error) *Error {
	if cause != nil && msg == "" {
		msg = cause.Error()
	}
	return &Error{Code: code, Message: msg, cause: cause}
}

// errorf is a convenience wrapper around newError for formatted messages.
func errorf(code ErrorCode, format string, args ...any) *Error {
	return newError(code, fmt.Sprintf(format, args...))
}
