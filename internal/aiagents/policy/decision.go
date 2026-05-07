package policy

// DecisionCode names a structured reason. Codes go to the JSONL audit
// record; the agent only sees Decision.UserMessage, which is intentionally
// generic.
type DecisionCode string

const (
	// Existing — npm-family registry-pinning verdicts.
	CodeAllowed            DecisionCode = "allowed"
	CodeRegistryNotAllowed DecisionCode = "registry_not_allowed"
	CodeRegistryFlag       DecisionCode = "registry_flag_override"
	CodeRegistryEnv        DecisionCode = "registry_env_override"
	CodeUserconfigFlag     DecisionCode = "userconfig_override"
	CodeManagedKeyMutation DecisionCode = "managed_key_mutation"
	CodeManagedKeyEdit     DecisionCode = "managed_key_edit"
	CodeInsufficientData   DecisionCode = "insufficient_data"
	CodePolicyDisabled     DecisionCode = "policy_disabled"
	CodeNotInstallCommand  DecisionCode = "not_install_command"

	// New — generic primitives evaluated before the registry path.
	// Each fires from a corresponding deny-list / allow-list field on
	// the Policy struct (see policy.go).
	CodeToolDenied            DecisionCode = "tool_denied"
	CodeCommandPatternDenied  DecisionCode = "command_pattern_denied"
	CodePathDenied            DecisionCode = "path_denied"
	CodeHostDenied            DecisionCode = "host_denied"
	CodeMCPServerDenied       DecisionCode = "mcp_server_denied"
	CodeCWDNotAllowed         DecisionCode = "cwd_not_allowed"
)

// GenericBlockMessage is the literal phrase shown to the agent on any
// block. It does not name files, registries, or packages — that detail
// goes to JSONL only, so the agent cannot guide the user to a bypass.
const GenericBlockMessage = "Blocked by your organization's administrator."

// Decision is the evaluator's output. Adapters consume only Allow and
// UserMessage; Code and InternalDetail are JSONL-only.
type Decision struct {
	Allow          bool
	Code           DecisionCode
	UserMessage    string
	InternalDetail string
}

// AllowDecision builds an explicit allow decision with the given code.
func AllowDecision(code DecisionCode, detail string) Decision {
	return Decision{Allow: true, Code: code, InternalDetail: detail}
}

// BlockDecision builds a block decision with the generic user message.
func BlockDecision(code DecisionCode, detail string) Decision {
	return Decision{
		Allow:          false,
		Code:           code,
		UserMessage:    GenericBlockMessage,
		InternalDetail: detail,
	}
}
