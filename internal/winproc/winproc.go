//go:build !windows

// Package winproc hides the console window of a child process on
// Windows. No-op on every other platform so call sites stay portable.
package winproc

import "os/exec"

// HideWindow is a no-op on non-Windows platforms.
func HideWindow(_ *exec.Cmd) {}
