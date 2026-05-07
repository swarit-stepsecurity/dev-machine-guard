package hooks

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// installForTest seeds the target home with DMG-owned hooks for the
// given agent. Returns the home directory used. Helper exists because
// most uninstall tests want a "previously installed" starting state.
func installForTest(t *testing.T, agent string) (home string, m *executor.Mock) {
	t.Helper()
	withEnterpriseConfig(t)
	withResolveBinary(t, okBinary)

	home = t.TempDir()
	m = newInstallMock(t, home)
	switch agent {
	case "claude-code":
		m.SetPath("claude", "/usr/local/bin/claude")
	case "codex":
		m.SetPath("codex", "/usr/local/bin/codex")
	case "both":
		m.SetPath("claude", "/usr/local/bin/claude")
		m.SetPath("codex", "/usr/local/bin/codex")
	}

	if _, herr := Install(context.Background(), m, ""); herr != nil {
		t.Fatalf("seed install failed: %v", herr)
	}
	return home, m
}

func TestUninstall_RootNoConsoleUser_ReturnsCode(t *testing.T) {
	logPath := withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := executor.NewMock()
	m.SetIsRoot(true)
	m.SetUsername("root")
	m.SetHomeDir("/var/root")

	_, herr := Uninstall(context.Background(), m, "")
	expectError(t, herr, CodeTargetUserUnresolved)
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "no_console_user") {
		t.Errorf("errlog missing no_console_user, got: %q", string(data))
	}
}

func TestUninstall_SelfPathFails_ReturnsCode(t *testing.T) {
	logPath := withErrorLog(t)
	withResolveBinary(t, func() (string, error) {
		return "", errors.New("mock selfpath failure")
	})

	m := newInstallMock(t, t.TempDir())
	_, herr := Uninstall(context.Background(), m, "")
	expectError(t, herr, CodeSelfPathFailed)
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "selfpath_failed") {
		t.Errorf("errlog missing selfpath_failed, got: %q", string(data))
	}
}

func TestUninstall_UnsupportedAgent_ReturnsCode(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := newInstallMock(t, t.TempDir())
	_, herr := Uninstall(context.Background(), m, "cursor")
	expectError(t, herr, CodeUnsupportedAgent)
}

func TestUninstall_NoAgentsDetected_ReturnsEmpty(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := newInstallMock(t, t.TempDir())
	results, herr := Uninstall(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("herr = %v, want nil", herr)
	}
	if len(results) != 0 {
		t.Errorf("expected empty result slice, got %d entries", len(results))
	}
}

// TestUninstall_NoEnterpriseConfigStillWorks pins the explicit uninstall
// design choice: revoking enterprise credentials must not trap users
// with hook entries pointing at a binary that can no longer authenticate.
// Default config vars are placeholders here — no withEnterpriseConfig —
// and uninstall must still proceed.
func TestUninstall_NoEnterpriseConfigStillWorks(t *testing.T) {
	// First seed Claude hooks WITH valid config (install requires it).
	home, m := installForTest(t, "claude-code")

	// Now drop the enterprise config and uninstall. The withEnterpriseConfig
	// cleanup from installForTest hasn't fired yet (still in the same
	// test), so we have to override directly.
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	if _, herr := Uninstall(context.Background(), m, ""); herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}

	// Verify the actual uninstall happened.
	settings := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file vanished after uninstall: %v", err)
	}
	if strings.Contains(string(data), fakeBinary+" _hook claude-code") {
		t.Errorf("DMG hook command still present after uninstall: %s", string(data))
	}
}

func TestUninstall_RemovesPreviouslyInstalledHooks(t *testing.T) {
	home, m := installForTest(t, "claude-code")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	settings := filepath.Join(home, ".claude", "settings.json")
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), fakeBinary+" _hook claude-code") {
		t.Fatalf("seed broken: install didn't write hook command: %s", string(before))
	}

	results, herr := Uninstall(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}
	if len(results) != 1 || results[0].Uninstall == nil || len(results[0].Uninstall.HooksRemoved) == 0 {
		t.Fatalf("expected per-agent UninstallResult with HooksRemoved set, got: %+v", results)
	}

	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file deleted after uninstall: %v", err)
	}
	if strings.Contains(string(after), fakeBinary+" _hook claude-code") {
		t.Errorf("DMG hook command not removed: %s", string(after))
	}
}

// TestUninstall_NoDMGOwnedEntries pins the no-op path: settings file
// exists, but contains no DMG-owned hook commands. Uninstall must
// succeed (nil error), surface the per-adapter "no DMG-owned" note,
// and leave the file byte-identical.
func TestUninstall_NoDMGOwnedEntries(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// User-authored settings with a third-party hook that DMG must NOT
	// match against its uninstall regex.
	settings := filepath.Join(claudeDir, "settings.json")
	original := []byte(`{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/other-tool/hook PreToolUse", "timeout": 5}]}
    ]
  }
}
`)
	if err := os.WriteFile(settings, original, 0o644); err != nil {
		t.Fatal(err)
	}

	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	results, herr := Uninstall(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}

	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file vanished: %v", err)
	}
	if !bytes.Equal(original, after) {
		t.Errorf("settings file mutated when no DMG hooks present:\nbefore=%s\nafter=%s", original, after)
	}

	// The Notes slice on the per-agent result must surface the no-op.
	if len(results) != 1 || len(results[0].Uninstall.Notes) == 0 {
		t.Fatalf("expected Notes set on no-op uninstall, got: %+v", results)
	}
	foundNote := false
	for _, n := range results[0].Uninstall.Notes {
		if strings.Contains(n, "no DMG-owned") {
			foundNote = true
			break
		}
	}
	if !foundNote {
		t.Errorf("Notes missing no-op message: %v", results[0].Uninstall.Notes)
	}
}

func TestUninstall_ExplicitAgentSkipsDetection(t *testing.T) {
	home, _ := installForTest(t, "codex")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	// Now use a fresh mock with EMPTY $PATH but --agent codex —
	// uninstall must still target codex.
	m := newInstallMock(t, home)
	if _, herr := Uninstall(context.Background(), m, "codex"); herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}

	hooksData, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hooksData), fakeBinary+" _hook codex") {
		t.Errorf("DMG codex hook still present: %s", string(hooksData))
	}
}

// TestUninstall_CodexLeavesFeatureFlag pins the invariant that uninstall
// removes hook entries from hooks.json but does NOT revert
// [features].codex_hooks=true in config.toml. Other tools' hooks may
// depend on that flag staying enabled.
func TestUninstall_CodexLeavesFeatureFlag(t *testing.T) {
	home, m := installForTest(t, "codex")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	cfgPath := filepath.Join(home, ".codex", "config.toml")
	beforeCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(beforeCfg), "codex_hooks") {
		t.Fatalf("seed broken: install didn't set codex_hooks flag: %s", string(beforeCfg))
	}

	results, herr := Uninstall(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}

	afterCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.toml vanished after uninstall: %v", err)
	}
	if !bytes.Equal(beforeCfg, afterCfg) {
		t.Errorf("config.toml mutated by uninstall:\nbefore=%s\nafter=%s",
			string(beforeCfg), string(afterCfg))
	}

	// The feature-flag-residue note must be visible to the caller via
	// the per-agent Uninstall.Notes slice so the residue isn't a silent
	// surprise.
	foundNote := false
	for _, r := range results {
		if r.Agent != "codex" || r.Uninstall == nil {
			continue
		}
		for _, n := range r.Uninstall.Notes {
			if strings.Contains(n, "feature flag left enabled") {
				foundNote = true
			}
		}
	}
	if !foundNote {
		t.Errorf("missing feature-flag residue note in results: %+v", results)
	}
}

// TestUninstall_NeverDeletesSettingsFile pins the invariant that even
// when uninstall removes every DMG-owned hook from a settings file that
// contains nothing else, the file itself must remain on disk.
func TestUninstall_NeverDeletesSettingsFile(t *testing.T) {
	home, m := installForTest(t, "claude-code")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	settings := filepath.Join(home, ".claude", "settings.json")

	if _, herr := Uninstall(context.Background(), m, ""); herr != nil {
		t.Fatalf("uninstall: %v", herr)
	}
	if _, err := os.Stat(settings); err != nil {
		t.Fatalf("settings file deleted: %v", err)
	}
}
