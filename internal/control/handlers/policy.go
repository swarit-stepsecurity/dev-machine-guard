package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/aiagents/atomicfile"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
	"github.com/step-security/dev-machine-guard/internal/control"
)

// CmdPolicyUpdate is the command name registered for `policy.update`.
// Backend dispatch (agent-api) gates fan-out on this exact string
// appearing in the daemon's hello-frame capabilities, so renaming
// breaks the wire contract.
const CmdPolicyUpdate = "policy.update"

// policyCacheFileName is the on-disk cache the _hook runtime reads
// from. Lives under ~/.stepsecurity alongside config.json.
const policyCacheFileName = "hook-policy.json"

// policyUpdateArgs is the args shape pushed by agent-api's
// dispatchHookPolicyChanges. `Scope` is informational ("device" today)
// and reserved so per-org / per-project scopes can land later without
// a wire-format break.
type policyUpdateArgs struct {
	Policy policy.Policy `json:"policy"`
	Etag   string        `json:"etag"`
	Scope  string        `json:"scope,omitempty"`
}

// policyUpdateResult is what we return on success. The etag echo lets
// the backend correlate the audit-log entry with the doc the daemon
// actually wrote — useful when retries / reconnect-syncs overlap.
type policyUpdateResult struct {
	Etag       string `json:"etag"`
	CachePath  string `json:"cache_path"`
	WroteBytes int    `json:"wrote_bytes"`
}

// PolicyUpdate writes an incoming policy doc to the on-disk cache so
// the next `dmg _hook` invocation reads the new rules without further
// network calls. Construction is deferred to NewPolicyUpdate so tests
// can pass a custom cacheDir.
type PolicyUpdate struct {
	cacheDir string
}

// NewPolicyUpdate returns the handler. cacheDir is normally empty,
// resolving to "~/.stepsecurity"; pass a non-empty value only from
// tests.
func NewPolicyUpdate(cacheDir string) *PolicyUpdate {
	return &PolicyUpdate{cacheDir: cacheDir}
}

// Name satisfies control.Handler.
func (h *PolicyUpdate) Name() string { return CmdPolicyUpdate }

// Execute deserializes args, validates the policy version, and writes
// the canonical doc to ~/.stepsecurity/hook-policy.json atomically.
//
// Errors map to wire codes:
//   - bad JSON / missing fields → CodeBadArgs (admin's PUT is malformed)
//   - filesystem failure        → CodeInternal (the daemon should retry on next push)
func (h *PolicyUpdate) Execute(ctx context.Context, args json.RawMessage) (any, error) {
	var p policyUpdateArgs
	if err := unmarshalArgs(args, &p); err != nil {
		return nil, err
	}
	if p.Etag == "" {
		return nil, control.NewHandlerError(control.CodeBadArgs, "policy.update: etag is required")
	}
	if p.Policy.Version == 0 {
		return nil, control.NewHandlerError(control.CodeBadArgs, "policy.update: policy.version is required")
	}

	dir, err := h.resolveCacheDir()
	if err != nil {
		return nil, control.WrapHandlerError(control.CodeInternal,
			fmt.Sprintf("resolve cache dir: %v", err), err)
	}
	cachePath := filepath.Join(dir, policyCacheFileName)

	// Persist the entire envelope (etag + policy) so subsequent loads
	// can dedupe without recomputing the hash. Wire shape doubles as
	// on-disk shape by design.
	envelope := struct {
		Etag   string        `json:"etag"`
		Policy policy.Policy `json:"policy"`
	}{Etag: p.Etag, Policy: p.Policy}

	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, control.WrapHandlerError(control.CodeInternal,
			fmt.Sprintf("marshal envelope: %v", err), err)
	}

	if _, err := atomicfile.WriteAtomic(cachePath, body, 0o600); err != nil {
		return nil, control.WrapHandlerError(control.CodeInternal,
			fmt.Sprintf("write %s: %v", cachePath, err), err)
	}

	return policyUpdateResult{
		Etag:       p.Etag,
		CachePath:  cachePath,
		WroteBytes: len(body),
	}, nil
}

// resolveCacheDir returns h.cacheDir if non-empty (test seam), else
// the user's ~/.stepsecurity directory.
func (h *PolicyUpdate) resolveCacheDir() (string, error) {
	if h.cacheDir != "" {
		return h.cacheDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".stepsecurity"), nil
}
