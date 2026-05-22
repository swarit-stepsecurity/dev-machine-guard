//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// AttachParentConsole re-wires os.Std* to the parent's console when
// one exists. The agent is GUI-subsystem (-H windowsgui) so Task
// Scheduler launches don't allocate a console — the no-flash property.
// The cost is no inherited stdio; this restores it for interactive
// runs from cmd.exe / PowerShell. Under Task Scheduler the parent has
// no console and this no-ops. Must run before any logging.
//
// Quirks for interactive use (also documented in README):
//   - Parent shell doesn't wait for GUI-subsystem children; output
//     streams async below the prompt. Use `Start-Process -Wait`.
//   - Pipes don't work — stdout is a console handle, not a pipe.
//   - $LASTEXITCODE / %ERRORLEVEL% unreliable without -Wait.
func AttachParentConsole() {
	const ATTACH_PARENT_PROCESS uint32 = 0xFFFFFFFF

	attach := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r1, _, _ := attach.Call(uintptr(ATTACH_PARENT_PROCESS)); r1 == 0 {
		return // no parent console; expected under Task Scheduler
	}

	if h, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0); err == nil {
		os.Stdout = os.NewFile(uintptr(h), "/dev/stdout")
	}
	if h, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0); err == nil {
		os.Stderr = os.NewFile(uintptr(h), "/dev/stderr")
	}
	if h, err := syscall.Open("CONIN$", syscall.O_RDWR, 0); err == nil {
		os.Stdin = os.NewFile(uintptr(h), "/dev/stdin")
	}
}
