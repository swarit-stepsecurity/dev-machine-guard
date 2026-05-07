package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const unitName = "stepsecurity-dev-machine-guard"

// Install configures a systemd user unit for the agent.
// When longRunning is false (default), installs an oneshot service + timer that
// fires every `config.ScanFrequencyHours`. When true, installs a single
// Type=simple service that runs `dmg daemon` and is restarted on failure.
// If already installed (either variant), upgrades by removing and re-creating.
func Install(exec executor.Executor, log *progress.Logger, longRunning bool) error {
	ctx := context.Background()

	// Check for existing installation and upgrade
	if isConfigured(ctx, exec) {
		log.Progress("Existing agent installation detected. Upgrading...")
		if err := doUninstall(ctx, exec, log); err != nil {
			log.Progress("Warning: failed to remove previous installation: %v", err)
		}
		log.Progress("Previous installation removed. Installing new version...")
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining binary path: %w", err)
	}

	hours, _ := strconv.Atoi(config.ScanFrequencyHours)
	if hours <= 0 {
		hours = 4
	}

	homeDir, _ := os.UserHomeDir()
	logDir := filepath.Join(homeDir, ".stepsecurity")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	unitDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("creating systemd user unit directory: %w", err)
	}

	data := unitTemplateData{
		BinaryPath: systemdEscape(binaryPath),
		LogDir:     systemdEscape(logDir),
		Hours:      hours,
	}

	if longRunning {
		return installLongRunning(ctx, exec, log, unitDir, logDir, data)
	}
	return installTimer(ctx, exec, log, unitDir, logDir, data, hours)
}

func installTimer(ctx context.Context, exec executor.Executor, log *progress.Logger, unitDir, logDir string, data unitTemplateData, hours int) error {
	servicePath := filepath.Join(unitDir, unitName+".service")
	if err := writeTemplate(servicePath, serviceTmpl, data); err != nil {
		return fmt.Errorf("writing service unit: %w", err)
	}

	timerPath := filepath.Join(unitDir, unitName+".timer")
	if err := writeTemplate(timerPath, timerTmpl, data); err != nil {
		return fmt.Errorf("writing timer unit: %w", err)
	}

	if err := daemonReload(ctx, exec); err != nil {
		return err
	}

	_, stderr, exitCode, err := exec.Run(ctx, "systemctl", "--user", "enable", "--now", unitName+".timer")
	if err != nil {
		return fmt.Errorf("failed to enable timer: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to enable timer (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("systemd user timer configuration completed successfully")
	log.Progress("  Service: %s", servicePath)
	log.Progress("  Timer:   %s", timerPath)
	log.Progress("  Logs:    %s/agent.log", logDir)
	log.Progress("Installation complete!")
	log.Progress("The agent will now run automatically every %d hours", hours)

	return nil
}

func installLongRunning(ctx context.Context, exec executor.Executor, log *progress.Logger, unitDir, logDir string, data unitTemplateData) error {
	// In long-running mode the service IS the agent — no timer.
	servicePath := filepath.Join(unitDir, unitName+".service")
	if err := writeTemplate(servicePath, longRunningServiceTmpl, data); err != nil {
		return fmt.Errorf("writing long-running service unit: %w", err)
	}

	if err := daemonReload(ctx, exec); err != nil {
		return err
	}

	// Enable linger before enabling the service. Without linger, the
	// user systemd manager terminates user units when the user's last
	// login session ends — which on a developer laptop happens every
	// time they log out, and on an MDM-deployed box happens whenever
	// the install SSH session exits. Best-effort: install proceeds
	// even if linger can't be enabled (we log a clear warning so the
	// operator knows to set it manually).
	enableLinger(ctx, exec, log)

	_, stderr, exitCode, err := exec.Run(ctx, "systemctl", "--user", "enable", "--now", unitName+".service")
	if err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to enable service (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("systemd user service (long-running) configuration completed successfully")
	log.Progress("  Service: %s", servicePath)
	log.Progress("  Logs:    %s/agent.log", logDir)
	log.Progress("Installation complete!")
	log.Progress("The agent is now running as a persistent service (experimental --long-running)")

	return nil
}

// enableLinger asks systemd-logind to keep this user's services
// running across login-session boundaries. Required for the
// long-running daemon — without it, the user systemd manager exits
// when the last session ends, taking the daemon with it.
//
// The call only succeeds when invoked as root or when polkit grants
// the user the `set-user-linger` action (typical for active console
// users on stock distros). On failure we log a clear remediation
// hint and continue: the install path stays usable, the daemon just
// won't survive logout until the user fixes it manually.
func enableLinger(ctx context.Context, exec executor.Executor, log *progress.Logger) {
	username := lingerTargetUser(exec)
	if username == "" {
		log.Warn("could not resolve target user for linger; run `loginctl enable-linger <user>` manually if the daemon stops on logout")
		return
	}
	if alreadyLingering(ctx, exec, username) {
		log.Progress("  Linger already enabled for %s", username)
		return
	}
	_, stderr, exitCode, err := exec.Run(ctx, "loginctl", "enable-linger", username)
	if err != nil {
		log.Warn("could not enable linger for %s: %v; run `sudo loginctl enable-linger %s` manually", username, err, username)
		return
	}
	if exitCode != 0 {
		log.Warn("could not enable linger for %s (exit %d): %s; run `sudo loginctl enable-linger %s` manually", username, exitCode, strings.TrimSpace(stderr), username)
		return
	}
	log.Progress("  Enabled linger for %s (daemon will survive logout)", username)
}

// lingerTargetUser picks the username to enable linger for. When the
// install runs as root (typical MDM deploy via the loader script),
// we want the actual console user — installing the daemon under
// root's home would defeat the whole point. When the install runs as
// the user themselves, we want their own username.
func lingerTargetUser(exec executor.Executor) string {
	if u, err := exec.LoggedInUser(); err == nil && u != nil && u.Username != "" {
		return u.Username
	}
	if u, err := exec.CurrentUser(); err == nil && u != nil && u.Username != "" {
		return u.Username
	}
	return ""
}

// alreadyLingering avoids a redundant enable-linger call (and its
// extra log line) when linger is already on. `loginctl show-user`
// emits `Linger=yes` / `Linger=no` regardless of whether the call
// is privileged, so this check is safe to make as either user.
func alreadyLingering(ctx context.Context, exec executor.Executor, username string) bool {
	stdout, _, _, err := exec.Run(ctx, "loginctl", "show-user", username, "--property=Linger")
	if err != nil {
		return false
	}
	return strings.Contains(stdout, "Linger=yes")
}

func daemonReload(ctx context.Context, exec executor.Executor) error {
	_, stderr, exitCode, err := exec.Run(ctx, "systemctl", "--user", "daemon-reload")
	if err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("daemon-reload failed (exit code %d): %s", exitCode, stderr)
	}
	return nil
}

// Uninstall removes the systemd user timer and service units.
func Uninstall(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	if !isConfigured(ctx, exec) {
		log.Progress("Agent is not currently configured for periodic execution")
		return nil
	}

	return doUninstall(ctx, exec, log)
}

func doUninstall(ctx context.Context, exec executor.Executor, log *progress.Logger) error {
	// Disable both the timer (classic mode) and the service (long-running
	// mode). Either may be missing depending on which install path was used;
	// disable returns non-zero in that case but we don't care.
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "disable", "--now", unitName+".timer")
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "disable", "--now", unitName+".service")
	log.Progress("Disabled systemd units")

	// Stop service in case it was started without enable.
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "stop", unitName+".service")

	// Remove unit files
	homeDir, _ := os.UserHomeDir()
	unitDir := filepath.Join(homeDir, ".config", "systemd", "user")
	for _, suffix := range []string{".service", ".timer"} {
		unitPath := filepath.Join(unitDir, unitName+suffix)
		if err := os.Remove(unitPath); err == nil {
			log.Progress("Removed %s", unitPath)
		}
	}

	// Reload
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "daemon-reload")

	log.Progress("systemd configuration removed successfully")
	return nil
}

func isConfigured(ctx context.Context, exec executor.Executor) bool {
	// Detect either install variant: timer (classic) or persistent service.
	if stdout, _, _, _ := exec.Run(ctx, "systemctl", "--user", "list-timers", "--no-pager"); strings.Contains(stdout, unitName) {
		return true
	}
	stdout, _, _, _ := exec.Run(ctx, "systemctl", "--user", "list-units", "--type=service", "--all", "--no-pager")
	return strings.Contains(stdout, unitName)
}

func writeTemplate(path, tmplStr string, data unitTemplateData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	tmpl, err := template.New("unit").Parse(tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(f, data)
}

type unitTemplateData struct {
	BinaryPath string // systemd-escaped (spaces replaced with \x20)
	LogDir     string
	Hours      int
}

// systemdEscape escapes a file path for use in systemd unit files.
// Spaces must be escaped as \x20 in ExecStart and related directives.
func systemdEscape(path string) string {
	return strings.ReplaceAll(path, " ", `\x20`)
}

const serviceTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard scan

[Service]
Type=oneshot
ExecStart={{.BinaryPath}} send-telemetry
StandardOutput=append:{{.LogDir}}/agent.log
StandardError=append:{{.LogDir}}/agent.error.log
`

const timerTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard periodic scan

[Timer]
OnBootSec=5min
OnUnitActiveSec={{.Hours}}h
Persistent=true

[Install]
WantedBy=timers.target
`

// longRunningServiceTmpl is the unit used by `install --long-running`. The
// binary's `daemon` subcommand owns the scan cadence in-process, so the unit
// itself has no timer; systemd just keeps it alive via Restart=on-failure.
const longRunningServiceTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard (long-running)

[Service]
Type=simple
ExecStart={{.BinaryPath}} daemon
Restart=on-failure
RestartSec=30s
StandardOutput=append:{{.LogDir}}/agent.log
StandardError=append:{{.LogDir}}/agent.error.log

[Install]
WantedBy=default.target
`
