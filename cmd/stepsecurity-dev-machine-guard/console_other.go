//go:build !windows

package main

// AttachParentConsole is a no-op on non-Windows.
func AttachParentConsole() {}
