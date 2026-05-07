package hooks

import (
	"context"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/selfpath"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// resolveBinary is the seam Install/Uninstall use to obtain the
// absolute, symlink-resolved DMG binary path. Production calls
// selfpath.Resolve(); tests override to avoid depending on a real
// on-disk binary or to drive the resolver-failure branch.
var resolveBinary = selfpath.Resolve

// Install installs DMG-managed hook entries into the agent settings
// file(s) for the requested agent (or every detected agent when agent
// is "").
//
// Returns []AgentResult — one entry per adapter the orchestrator
// considered. Status="ok" means the adapter wrote its hooks; "skipped"
// means the agent's CLI binary was not on $PATH (only on the default
// fan-out path; explicit --agent always runs); "error" means the
// adapter's Install returned an error.
//
// Returns *Error when the orchestration itself failed before any
// adapter ran (enterprise config missing, self-path resolution failure,
// no console user under root, unsupported agent name). Adapter-level
// failures populate AgentResult.Error and aggregate to
// CodeAdapterInstallFailed in the returned *Error so callers don't have
// to scan the slice.
//
// Callers should consider StatusError + CodeTargetUserUnresolved a
// no-op success (matches the historical CLI exit-0 behavior).
func Install(ctx context.Context, exec executor.Executor, agent string) ([]AgentResult, *Error) {
	if _, ok := ingest.Snapshot(); !ok {
		errlog.AppendError("install", "enterprise_config_missing", "ingest.Snapshot returned not-ok", "")
		return nil, newError(CodeEnterpriseConfigMissing,
			"enterprise configuration not found or incomplete; run `configure`")
	}

	target, terr := resolveTargetUser(exec)
	if terr != nil {
		return nil, terr
	}

	binaryPath, err := resolveBinary()
	if err != nil {
		errlog.AppendError("install", "selfpath_failed", err.Error(), "")
		return nil, wrapError(CodeSelfPathFailed, "cannot resolve own binary path", err)
	}

	adapters, err := selectAdapters(ctx, agent, target.HomeDir, binaryPath, exec)
	if err != nil {
		errlog.AppendError("install", "select_adapters_failed", err.Error(), "")
		return nil, wrapError(CodeUnsupportedAgent, "select adapters", err)
	}

	results := make([]AgentResult, 0, len(adapters))
	if len(adapters) == 0 {
		// No agents detected on $PATH and no explicit --agent. Return an
		// empty slice + nil error — caller decides UX (CLI prints the
		// "no agents detected" message; control plane returns ok with
		// data=[]).
		return results, nil
	}

	anyFailed := false
	for _, a := range adapters {
		ar := AgentResult{Agent: a.Name(), Status: StatusOK}
		res, err := a.Install(ctx)
		if err != nil {
			errlog.AppendError("install", "adapter_install_failed",
				fmt.Sprintf("%s: %v", a.Name(), err), "")
			ar.Status = StatusError
			ar.Error = err.Error()
			results = append(results, ar)
			anyFailed = true
			// Skip chown on failure: partial state is already
			// inconsistent, and a chown sweep can't unbreak it.
			continue
		}
		// Under root, chown every file written or created. ChownToTarget
		// short-circuits to a no-op when not root.
		chownToTarget(exec, installChownPaths(res), target)
		ar.Install = &res
		results = append(results, ar)
	}

	if anyFailed {
		return results, newError(CodeAdapterInstallFailed,
			"one or more adapters failed; see per-agent results")
	}
	return results, nil
}

// installChownPaths is the chown sweep set for a single adapter's
// InstallResult. Order is shallowest-parent-first (CreatedDirs are
// pushed by the adapter in that order) so a recursive chown could
// stop at a parent without revisiting children — though the current
// helper chowns each entry individually.
func installChownPaths(r adapter.InstallResult) []string {
	out := make([]string, 0, len(r.CreatedDirs)+len(r.WrittenFiles)+len(r.BackupFiles))
	out = append(out, r.CreatedDirs...)
	out = append(out, r.WrittenFiles...)
	out = append(out, r.BackupFiles...)
	return out
}
