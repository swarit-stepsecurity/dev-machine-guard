package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/hooks"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// RunInstall is the entry point for `hooks install`.
//
// agent is the --agent flag value; "" means "every detected agent".
// stdout/stderr are the writers main wires from os.Stdout/os.Stderr.
//
// Returns the desired process exit code:
//   - 0 on success, no agents detected, or the no-console-user no-op.
//   - 1 on enterprise-config gate failure, self-path resolution failure,
//     unsupported --agent, or any adapter Install error.
//
// All orchestration lives in internal/aiagents/hooks.Install; this
// function is a thin presenter that maps the typed result to formatted
// output and an exit code. The control-plane WS handler calls
// hooks.Install directly without any of this presentation.
func RunInstall(ctx context.Context, exec executor.Executor, agent string, stdout, stderr io.Writer) int {
	results, err := hooks.Install(ctx, exec, agent)
	return present(stdout, stderr, "install", results, err, presentInstall)
}

// present is the shared presenter for hooks.Install / hooks.Uninstall
// results. It maps the typed *hooks.Error into stderr lines + an exit
// code, then walks the per-agent slice via printOne.
func present(
	stdout, stderr io.Writer,
	verb string,
	results []hooks.AgentResult,
	herr *hooks.Error,
	printOne func(io.Writer, hooks.AgentResult),
) int {
	if herr != nil {
		switch herr.Code {
		case hooks.CodeEnterpriseConfigMissing:
			fmt.Fprintln(stderr, "Enterprise configuration not found or incomplete.")
			fmt.Fprintln(stderr, "Run `stepsecurity-dev-machine-guard configure` to set customer_id, api_endpoint, and api_key.")
			return 1
		case hooks.CodeTargetUserUnresolved:
			fmt.Fprintln(stderr, "stepsecurity-dev-machine-guard: running as root with no console user; nothing to install.")
			return 0
		case hooks.CodeSelfPathFailed:
			fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %s\n", herr.Error())
			return 1
		case hooks.CodeUnsupportedAgent:
			cause := errors.Unwrap(herr)
			if cause != nil {
				fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %v\n", cause)
			} else {
				fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %s\n", herr.Error())
			}
			return 1
		case hooks.CodeAdapterInstallFailed, hooks.CodeAdapterUninstallFailed:
			// Adapter-level errors — fall through to per-agent printing
			// so the user can see which one failed and why.
		default:
			fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %s: %s\n", verb, herr.Error())
			return 1
		}
	}

	if len(results) == 0 && herr == nil {
		fmt.Fprintln(stdout, "No supported AI coding agents detected on $PATH.")
		fmt.Fprintf(stdout, "Pass --agent <name> to %s for a specific agent (supported: %s).\n",
			verb, strings.Join(hooks.SupportedAgents, ", "))
		return 0
	}

	exit := 0
	for _, r := range results {
		if r.Status == hooks.StatusError {
			exit = 1
			fmt.Fprintf(stderr, "%s: %s failed: %s\n", r.Agent, verb, r.Error)
			continue
		}
		printOne(stdout, r)
	}
	return exit
}

func presentInstall(w io.Writer, r hooks.AgentResult) {
	fmt.Fprintf(w, "%s:\n", r.Agent)
	if r.Install == nil {
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
		return
	}
	if len(r.Install.HooksAdded) > 0 {
		fmt.Fprintf(w, "  added: %v\n", r.Install.HooksAdded)
	}
	if len(r.Install.HooksKept) > 0 {
		fmt.Fprintf(w, "  unchanged: %v\n", r.Install.HooksKept)
	}
	for _, f := range r.Install.WrittenFiles {
		fmt.Fprintf(w, "  wrote: %s\n", f)
	}
	for _, f := range r.Install.BackupFiles {
		fmt.Fprintf(w, "  backup: %s\n", f)
	}
	for _, n := range r.Install.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}
