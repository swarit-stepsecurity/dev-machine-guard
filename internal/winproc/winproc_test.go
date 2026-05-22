package winproc

import (
	"os/exec"
	"testing"
)

func TestHideWindow_NilSafe(t *testing.T) {
	HideWindow(nil)
}

func TestHideWindow_ZeroValueCmd(t *testing.T) {
	cmd := exec.Command("true")
	HideWindow(cmd)
	if cmd.Path == "" {
		t.Fatal("HideWindow corrupted cmd.Path")
	}
}
