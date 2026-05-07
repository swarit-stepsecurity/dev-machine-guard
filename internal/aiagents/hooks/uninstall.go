package hooks

import (
	"context"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Uninstall removes DMG-managed hook entries from the agent settings
// file(s) for the requested agent (or every detected agent when agent
// is "").
//
// No enterprise-config gate: uninstall must work even after the
// customer has revoked credentials or rotated keys — otherwise we'd
// trap users with hook entries pointing at a binary that can no longer
// authenticate.
//
// Result semantics mirror Install: per-agent AgentResult with
// Status="ok" when the adapter rewrote its settings (or was a clean
// no-op), "skipped" on default fan-out when the agent's CLI is not on
// $PATH, "error" when the adapter's Uninstall returned an error.
// Returned *Error is non-nil only on orchestration-level failure
// (self-path, target user, unsupported agent, or aggregate adapter
// failure).
func Uninstall(ctx context.Context, exec executor.Executor, agent string) ([]AgentResult, *Error) {
	target, terr := resolveTargetUser(exec)
	if terr != nil {
		return nil, terr
	}

	binaryPath, err := resolveBinary()
	if err != nil {
		errlog.AppendError("uninstall", "selfpath_failed", err.Error(), "")
		return nil, wrapError(CodeSelfPathFailed, "cannot resolve own binary path", err)
	}

	adapters, err := selectAdapters(ctx, agent, target.HomeDir, binaryPath, exec)
	if err != nil {
		errlog.AppendError("uninstall", "select_adapters_failed", err.Error(), "")
		return nil, wrapError(CodeUnsupportedAgent, "select adapters", err)
	}

	results := make([]AgentResult, 0, len(adapters))
	if len(adapters) == 0 {
		return results, nil
	}

	anyFailed := false
	for _, a := range adapters {
		ar := AgentResult{Agent: a.Name(), Status: StatusOK}
		res, err := a.Uninstall(ctx)
		if err != nil {
			errlog.AppendError("uninstall", "adapter_uninstall_failed",
				fmt.Sprintf("%s: %v", a.Name(), err), "")
			ar.Status = StatusError
			ar.Error = err.Error()
			results = append(results, ar)
			anyFailed = true
			continue
		}
		// Same chown rationale as install: a sudo-driven rewrite must
		// not leave the user's settings owned by root. UninstallResult
		// never carries CreatedDirs — uninstall only rewrites files
		// that already existed.
		chownToTarget(exec, uninstallChownPaths(res), target)
		ar.Uninstall = &res
		results = append(results, ar)
	}

	if anyFailed {
		return results, newError(CodeAdapterUninstallFailed,
			"one or more adapters failed; see per-agent results")
	}
	return results, nil
}

// uninstallChownPaths is the chown sweep set for a single adapter's
// UninstallResult. WrittenFiles ∪ BackupFiles only — uninstall never
// creates new directories.
func uninstallChownPaths(r adapter.UninstallResult) []string {
	out := make([]string, 0, len(r.WrittenFiles)+len(r.BackupFiles))
	out = append(out, r.WrittenFiles...)
	out = append(out, r.BackupFiles...)
	return out
}
