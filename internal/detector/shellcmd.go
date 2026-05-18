package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// runShellCmd runs a shell command string using the platform-appropriate shell.
// On Unix: bash -c "command"
// On Windows: cmd /c "command"
func runShellCmd(ctx context.Context, exec executor.Executor, timeout time.Duration, command string) (string, string, int, error) {
	if exec.GOOS() == "windows" {
		return exec.RunWithTimeout(ctx, timeout, "cmd", "/c", command)
	}
	return exec.RunWithTimeout(ctx, timeout, "bash", "-c", command)
}

// runCmdInDir runs a command from a specific working directory. On Windows it
// dispatches directly via the executor's RunInDir (using os/exec's cmd.Dir),
// avoiding the `cmd /c "cd <dir> && <cmd>"` pattern — Go's os/exec quoting and
// cmd.exe's quote-stripping rules conflict when paths or arguments need
// escaping, producing "The filename, directory name, or volume label syntax
// is incorrect." On Unix we keep the shell-command-string approach so root
// runs can still delegate via RunAsUser/sudo.
func runCmdInDir(ctx context.Context, exec executor.Executor, timeout time.Duration, dir, name string, args ...string) (string, string, int, error) {
	if exec.GOOS() == "windows" {
		return exec.RunInDir(ctx, timeout, dir, name, args...)
	}
	shellCmd := "cd " + platformShellQuote(exec, dir) + " && " + name
	for _, a := range args {
		shellCmd += " " + a
	}
	return runShellCmd(ctx, exec, timeout, shellCmd)
}

// platformShellQuote quotes a string for use in a shell command.
// On Unix: single quotes with escaping.
// On Windows: double quotes with escaping.
func platformShellQuote(exec executor.Executor, s string) string {
	if exec.GOOS() == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
