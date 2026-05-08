package hook

import (
	"context"
	"os"
	"sync"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
)

// homeDirOnce caches the user's home directory for the lifetime of
// this _hook subprocess. ~/ expansion in path / cwd patterns happens
// on every PreToolUse; reading the env var once amortizes the cost.
var (
	homeDirCache string
	homeDirRead  sync.Once
)

func homeDirOnce() string {
	homeDirRead.Do(func() {
		if h, err := os.UserHomeDir(); err == nil {
			homeDirCache = h
		}
	})
	return homeDirCache
}

// shouldEvaluatePolicy is the cheap filter that runs before any I/O.
// Fires on EVERY PreToolUse event, regardless of which tool — the
// generic-primitive matchers (DenyTools, DenyPaths, DenyHosts, …)
// need to see WebFetch, Read, Write, mcp__… calls too, not just
// shell-command exec.
//
// Normalized over hook_phase so future agents reuse it without
// branching on Claude-specific hook names. Action / shell content
// checks now live inside individual matchers — empty inputs no-op
// gracefully.
func shouldEvaluatePolicy(ev *event.Event, _ string) bool {
	return ev != nil && ev.HookPhase == event.HookPhasePreTool
}

// evaluatePolicy is the stage between enrichment and upload. It returns
// (nil, AllowDecision) when the observed binary does not belong to a
// known ecosystem, when the ecosystem block is disabled, when the command
// is not policy-relevant, or when any internal step fails — fail-open is
// preserved on every error path.
//
// The returned adapter.Decision is the *effective* response. The
// evaluator forces ModeAudit before consulting the verdict, so block
// decisions never escape this function. The block code path remains
// exercised by tests that inject a Policy with Mode=block; production
// builds never set it.
func (rt *Runtime) evaluatePolicy(_ context.Context, ev *event.Event, cmd string) (*event.PolicyDecisionInfo, adapter.Decision) {
	allow := adapter.AllowDecision()

	// Load prefers ~/.stepsecurity/hook-policy.json (populated by the
	// daemon's policy.update handler) and falls back to the embedded
	// baseline when the cache is missing or corrupt. A non-nil error
	// here means the file existed but couldn't be parsed — log it via
	// errlog so the operator notices, but continue with Builtin().
	pol, loadErr := policy.Load()
	if loadErr != nil {
		errlog.AppendError("policy_cache_load", "load_failed", loadErr.Error(), "")
	}
	if rt.Policy != nil {
		pol = *rt.Policy
	}

	// Build a Request that carries BOTH the generic-primitive inputs
	// (any tool, file paths, URLs, MCP servers, CWD) AND the existing
	// ecosystem-specific fields (only populated for shell tool calls
	// in an enforced npm-family ecosystem).
	req := buildPolicyRequest(ev, cmd)

	// Skip the eval entirely when neither generic-primitive lists nor
	// an enforced ecosystem could possibly fire — keeps the audit
	// signal unchanged for events the policy has nothing to say about.
	if !policyHasAnyRule(pol) && req.Ecosystem == "" {
		return nil, allow
	}

	verdict := policy.Eval(pol, req)

	// CodePolicyDisabled / CodeNotInstallCommand / CodeInsufficientData
	// are "allow because nothing applied" — return nil so the runtime
	// doesn't stamp policy_decision on every event for nothing.
	if verdict.Allow && isInformationalCode(verdict.Code) {
		return nil, allow
	}

	mode := policy.ResolveMode(pol)
	wouldBlock := !verdict.Allow
	enforced := wouldBlock && mode == policy.ModeBlock

	info := &event.PolicyDecisionInfo{
		Mode:           string(mode),
		Allowed:        !enforced,
		WouldBlock:     wouldBlock,
		Enforced:       enforced,
		Code:           string(verdict.Code),
		InternalDetail: verdict.InternalDetail,
		Registry:       req.Registry,
		AllowlistHit:   verdict.Allow && req.Registry != "",
		Bypass:         bypassFor(verdict.Code),
	}
	if enforced {
		return info, adapter.Decision{Allow: false, UserMessage: verdict.UserMessage}
	}
	return info, allow
}

// buildPolicyRequest assembles a policy.Request from the event +
// shell command. Fields not relevant to the current event are left
// zero-valued; matchers no-op on those cleanly.
func buildPolicyRequest(ev *event.Event, cmd string) policy.Request {
	req := policy.Request{
		ToolName:     ev.ToolName,
		ShellCommand: cmd,
		CWD:          ev.WorkingDirectory,
		HomeDir:      homeDirOnce(),
	}

	// Pull file path / URL out of the redacted payload when present.
	// We don't trust unredacted user input here; redact.Value already
	// ran in the runtime before we get called.
	if ev.Payload != nil {
		if ti, ok := ev.Payload["tool_input"].(map[string]any); ok {
			req.FilePath = firstNonEmptyString(ti, "file_path", "path", "filename")
			req.URL = firstNonEmptyString(ti, "url")
		}
	}

	// Ecosystem-specific fields — only populated when this looks like
	// a shell tool call AND the parsed binary maps to an ecosystem.
	if cmd != "" {
		parsed := policy.ParseShell(cmd)
		if eco := policy.EcosystemFor(parsed.Binary); eco != "" {
			req.Ecosystem = eco
			req.PackageManager = normalizePM(parsed.Binary)
			req.CommandKind = commandKindFor(parsed, ev)
			req.RegistryFlag = parsed.RegistryFlag
			req.UserconfigFlag = parsed.UserconfigFlag
			req.InlineEnv = parsed.InlineEnv
			if parsed.ConfigOp != "" {
				req.ConfigKeyMutated = parsed.ConfigKey
				req.ConfigValue = parsed.ConfigValue
			}
			if ev.Enrichments != nil && ev.Enrichments.PackageManager != nil {
				req.Registry = ev.Enrichments.PackageManager.Registry
			}
		}
	}
	return req
}

// policyHasAnyRule reports whether the policy carries at least one
// rule that could plausibly fire. Empty / unset everywhere ⇒ false ⇒
// short-circuit before policy.Eval allocates anything.
func policyHasAnyRule(p policy.Policy) bool {
	if len(p.DenyTools) > 0 || len(p.DenyCommandPatterns) > 0 ||
		len(p.DenyPaths) > 0 || len(p.DenyHosts) > 0 ||
		len(p.DenyMCPServers) > 0 || len(p.AllowCWDs) > 0 {
		return true
	}
	for _, eco := range p.Ecosystems {
		if eco.Enabled {
			return true
		}
	}
	return false
}

// isInformationalCode reports whether a verdict code corresponds to
// "no rule applied / nothing to say". Used to suppress
// policy_decision stamping on quiet events.
func isInformationalCode(code policy.DecisionCode) bool {
	switch code {
	case policy.CodePolicyDisabled,
		policy.CodeNotInstallCommand,
		policy.CodeInsufficientData,
		policy.CodeAllowed:
		// CodeAllowed is meaningful when we DID act (registry
		// allowlist hit, etc.); the runtime keeps stamping for it.
		// Listed here so a pure-allow verdict from the generic path
		// (when no list was matched) doesn't get suppressed — but
		// the generic path returns allow with no code today, so this
		// branch is only hit for the ecosystem path.
		return code != policy.CodeAllowed
	}
	return false
}

// firstNonEmptyString returns the first value from m matching one of
// the given keys, when that value is a non-empty string.
func firstNonEmptyString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// commandKindFor maps a parsed-shell shape onto the policy.Request kind
// vocabulary. Config ops win because the parser detects them with high
// specificity; otherwise we fall back to whatever npm.Enrich classified.
func commandKindFor(parsed policy.ParsedCommand, ev *event.Event) string {
	switch parsed.ConfigOp {
	case "set":
		return "config_set"
	case "delete":
		return "config_delete"
	case "edit":
		return "config_edit"
	}
	if ev.Enrichments != nil && ev.Enrichments.PackageManager != nil {
		if k := ev.Enrichments.PackageManager.CommandKind; k != "" {
			return k
		}
	}
	return "other"
}

// normalizePM collapses execution-only siblings onto their config-owning
// counterpart so managed-key lookups in policy.Eval find the right table.
// `npx` does not own configuration; `npm` does.
func normalizePM(bin string) string {
	switch bin {
	case "npx":
		return "npm"
	case "pnpx":
		return "pnpm"
	case "bunx":
		return "bun"
	}
	return bin
}

// bypassFor maps a policy decision code onto the audit-only Bypass tag.
// Returns "" for non-bypass codes (allow, missing data, etc).
func bypassFor(code policy.DecisionCode) string {
	switch code {
	case policy.CodeRegistryFlag:
		return "registry_flag"
	case policy.CodeRegistryEnv:
		return "env_var"
	case policy.CodeUserconfigFlag:
		return "userconfig_flag"
	case policy.CodeManagedKeyMutation:
		return "config_set"
	case policy.CodeManagedKeyEdit:
		return "config_edit"
	}
	return ""
}
