//go:build windows

package winproc

import (
	"os/exec"
	"syscall"
)

const createNoWindow uint32 = 0x08000000

// HideWindow sets HideWindow + CREATE_NO_WINDOW on cmd. Without this,
// powershell/cmd/.cmd subprocesses Go spawns under Task Scheduler
// flash a console window. Merges with existing SysProcAttr; idempotent.
func HideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
