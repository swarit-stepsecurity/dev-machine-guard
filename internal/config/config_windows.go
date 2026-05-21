//go:build windows

package config

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// machineConfigDir is the machine-wide config location on Windows. The
// path is hardcoded (not derived from %PROGRAMDATA%) so it matches what
// the MSI WiX manifest hardcodes — keeping installer and binary in sync.
func machineConfigDir() string {
	return `C:\ProgramData\StepSecurity`
}

// isElevated reports whether the current process holds an elevated token
// (admin rights / UAC-elevated). MSI custom actions running deferred with
// Impersonate=no execute under LocalSystem, which is elevated.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// hardenMachineConfigACL locks down the machine-wide config.json with an
// explicit ACL: SYSTEM + Administrators get Full; BUILTIN\Users gets Read
// (so the scheduled task running as the logged-in user can still load it),
// inheritance is disabled, and the file is not writable by non-admins.
// POSIX file-mode bits we set in save() don't actually enforce anything on
// Windows; this is what does. Mirrors the icacls pattern used in
// internal/schtasks/schtasks.go for the agent.log directory.
//
// Best-effort: a non-zero icacls exit is logged but does not fail the
// configure call — the config is still functional with default inherited
// ProgramData ACLs (which are also Administrators/SYSTEM full + Users
// read-and-execute on existing files, just not as tightly scoped).
func hardenMachineConfigACL(path string) error {
	args := []string{
		path,
		"/inheritance:r",          // remove inherited ACEs
		"/grant:r", "*S-1-5-18:F", // NT AUTHORITY\SYSTEM = Full
		"/grant:r", "*S-1-5-32-544:F", // BUILTIN\Administrators = Full
		"/grant:r", "*S-1-5-32-545:R", // BUILTIN\Users = Read
		"/Q",
	}
	return exec.Command("icacls", args...).Run()
}
