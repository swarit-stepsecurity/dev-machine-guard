package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/step-security/dev-machine-guard/internal/aiagents/hooks"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// RunUninstall is the entry point for `hooks uninstall`.
//
// agent is the --agent flag value; "" means "every detected agent".
// stdout/stderr are wired from os.Stdout/os.Stderr by main.
//
// Returns the desired process exit code:
//   - 0 on success, no-op (no DMG-owned entries found), no agents
//     detected, or the no-console-user no-op.
//   - 1 on self-path resolution failure, unsupported --agent, or any
//     adapter Uninstall error.
//
// All orchestration lives in internal/aiagents/hooks.Uninstall; this
// is a thin presenter. The control-plane WS handler calls
// hooks.Uninstall directly.
//
// No enterprise-config gate: uninstall must work even after the
// customer has revoked credentials or rotated keys — see the matching
// note on hooks.Uninstall.
func RunUninstall(ctx context.Context, exec executor.Executor, agent string, stdout, stderr io.Writer) int {
	results, err := hooks.Uninstall(ctx, exec, agent)
	return present(stdout, stderr, "uninstall", results, err, presentUninstall)
}

func presentUninstall(w io.Writer, r hooks.AgentResult) {
	fmt.Fprintf(w, "%s:\n", r.Agent)
	if r.Uninstall == nil {
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
		return
	}
	if len(r.Uninstall.HooksRemoved) > 0 {
		fmt.Fprintf(w, "  removed: %v\n", r.Uninstall.HooksRemoved)
	}
	for _, f := range r.Uninstall.WrittenFiles {
		fmt.Fprintf(w, "  wrote: %s\n", f)
	}
	for _, f := range r.Uninstall.BackupFiles {
		fmt.Fprintf(w, "  backup: %s\n", f)
	}
	for _, n := range r.Uninstall.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}
