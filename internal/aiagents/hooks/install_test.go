package hooks

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// withErrorLog redirects the errors log to a temp path for the test and
// restores the previous value on cleanup. Tests using this helper must
// not run in parallel — the override is package-level state in errlog.
func withErrorLog(t *testing.T) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "errors.jsonl")
	prev := errlog.PathOverride()
	errlog.SetPathOverride(tmp)
	t.Cleanup(func() { errlog.SetPathOverride(prev) })
	return tmp
}

// withEnterpriseConfig stages valid (non-empty, non-placeholder) values
// in the package-level config vars that ingest.Snapshot reads, restoring
// the previous values on cleanup. Tests using this helper must not run
// in parallel — config vars are package-level state.
func withEnterpriseConfig(t *testing.T) {
	t.Helper()
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	config.CustomerID = "cust-test"
	config.APIEndpoint = "https://api.example.com"
	config.APIKey = "secret-test"
	t.Cleanup(func() {
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})
}

// withResolveBinary overrides the install-time selfpath resolver with a
// fixed value (or error). The default Resolve() reads os.Executable
// which under `go test` points at the test binary — fine in principle,
// but pinning a known value keeps the hook commands written to settings
// readable in failure output.
func withResolveBinary(t *testing.T, fn func() (string, error)) {
	t.Helper()
	prev := resolveBinary
	resolveBinary = fn
	t.Cleanup(func() { resolveBinary = prev })
}

const fakeBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

func okBinary() (string, error) { return fakeBinary, nil }

// newInstallMock returns a Mock executor configured as a non-root user
// whose home is `home`. Callers add SetPath entries for the agents they
// want detected.
func newInstallMock(t *testing.T, home string) *executor.Mock {
	t.Helper()
	m := executor.NewMock()
	m.SetIsRoot(false)
	m.SetUsername("alice")
	m.SetHomeDir(home)
	return m
}

// expectError asserts the call returned a non-nil *Error with the
// expected code. Failure prints both the wanted and actual codes plus
// the message body for debugging.
func expectError(t *testing.T, herr *Error, want ErrorCode) {
	t.Helper()
	if herr == nil {
		t.Fatalf("expected *Error with code %q, got nil", want)
	}
	if herr.Code != want {
		t.Fatalf("error code = %q, want %q (message=%q)", herr.Code, want, herr.Message)
	}
}

func TestInstall_NoEnterpriseConfig_ReturnsCode(t *testing.T) {
	logPath := withErrorLog(t)
	// Leave config vars as their default placeholders ({{...}}) — no
	// withEnterpriseConfig call. ingest.Snapshot returns ok=false on
	// placeholders.
	m := executor.NewMock()
	_, herr := Install(context.Background(), m, "")
	expectError(t, herr, CodeEnterpriseConfigMissing)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errors log entry: %v", err)
	}
	if !strings.Contains(string(data), "enterprise_config_missing") {
		t.Errorf("errlog missing code, got: %q", string(data))
	}
}

func TestInstall_PlaceholderConfig_ReturnsCode(t *testing.T) {
	withErrorLog(t)
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	config.CustomerID = "cust-1"
	config.APIEndpoint = "{{API_ENDPOINT}}"
	config.APIKey = "secret"
	t.Cleanup(func() {
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})

	m := executor.NewMock()
	_, herr := Install(context.Background(), m, "")
	expectError(t, herr, CodeEnterpriseConfigMissing)
}

func TestInstall_RootNoConsoleUser_ReturnsCode(t *testing.T) {
	withEnterpriseConfig(t)
	logPath := withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := executor.NewMock()
	m.SetIsRoot(true)
	// "root" simulates the executor failing to resolve a console user.
	m.SetUsername("root")
	m.SetHomeDir("/var/root")

	_, herr := Install(context.Background(), m, "")
	expectError(t, herr, CodeTargetUserUnresolved)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errlog entry on root-no-console-user: %v", err)
	}
	if !strings.Contains(string(data), "no_console_user") {
		t.Errorf("errlog missing no_console_user code, got: %q", string(data))
	}
}

func TestInstall_SelfPathFails_ReturnsCode(t *testing.T) {
	withEnterpriseConfig(t)
	logPath := withErrorLog(t)
	withResolveBinary(t, func() (string, error) {
		return "", errors.New("mock selfpath failure")
	})

	home := t.TempDir()
	m := newInstallMock(t, home)

	_, herr := Install(context.Background(), m, "")
	expectError(t, herr, CodeSelfPathFailed)
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "selfpath_failed") {
		t.Errorf("errlog missing selfpath_failed code, got: %q", string(data))
	}
}

func TestInstall_UnsupportedAgent_ReturnsCode(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)

	_, herr := Install(context.Background(), m, "cursor")
	expectError(t, herr, CodeUnsupportedAgent)
	// The wrapped cause should mention the rejected name so callers
	// rendering UX can surface it without re-parsing the code.
	if cause := errors.Unwrap(herr); cause == nil || !strings.Contains(cause.Error(), "cursor") {
		t.Errorf("expected wrapped cause to name the rejected agent, got: %v", cause)
	}
}

func TestInstall_NoAgentsDetected_ReturnsEmpty(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home) // no SetPath, nothing detected

	results, herr := Install(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("herr = %v, want nil", herr)
	}
	if len(results) != 0 {
		t.Errorf("expected empty result slice, got %d entries: %+v", len(results), results)
	}
}

func TestInstall_InstallsClaudeCode(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	results, herr := Install(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("herr = %v, want nil", herr)
	}
	if len(results) != 1 || results[0].Agent != "claude-code" || results[0].Status != StatusOK {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].Install == nil || len(results[0].Install.HooksAdded) == 0 {
		t.Errorf("expected Install with HooksAdded set: %+v", results[0])
	}

	settings := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("expected settings file written at %s: %v", settings, err)
	}
	// The hook command must include the resolved binary path AND the
	// canonical `_hook claude-code` invocation prefix — that's what
	// uninstall later matches against.
	if !strings.Contains(string(data), fakeBinary+" _hook claude-code") {
		t.Errorf("settings missing hook command, got: %s", string(data))
	}
}

func TestInstall_InstallsBoth(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")
	m.SetPath("codex", "/usr/local/bin/codex")

	results, herr := Install(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("herr = %v, want nil", herr)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %+v", len(results), results)
	}
	// Results follow SupportedAgents declaration order — claude-code first.
	if results[0].Agent != "claude-code" || results[1].Agent != "codex" {
		t.Errorf("unexpected ordering: %v, %v", results[0].Agent, results[1].Agent)
	}

	for _, p := range []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".codex", "hooks.json"),
		filepath.Join(home, ".codex", "config.toml"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file written: %s (err=%v)", p, err)
		}
	}
}

func TestInstall_ExplicitAgentSkipsDetection(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	// PATH is empty — but --agent codex is an unconditional opt-in.
	m := newInstallMock(t, home)

	results, herr := Install(context.Background(), m, "codex")
	if herr != nil {
		t.Fatalf("herr = %v, want nil", herr)
	}
	if len(results) != 1 || results[0].Agent != "codex" || results[0].Status != StatusOK {
		t.Fatalf("unexpected: %+v", results)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "hooks.json")); err != nil {
		t.Errorf("expected codex hooks.json: %v", err)
	}
	// Claude must NOT have been touched.
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("claude settings should not exist on explicit --agent codex; err=%v", err)
	}
}

func TestInstall_IdempotentReinstall(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	if _, herr := Install(context.Background(), m, ""); herr != nil {
		t.Fatalf("first install: %v", herr)
	}

	settings := filepath.Join(home, ".claude", "settings.json")
	first, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}

	results, herr := Install(context.Background(), m, "")
	if herr != nil {
		t.Fatalf("second install: %v", herr)
	}

	second, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	// A reinstall pretty-prints into canonical formatting; what we
	// care about is byte-stability across two reinstalls — that
	// confirms upsertHook produced no spurious diff after settling.
	if !bytes.Equal(first, second) {
		t.Errorf("settings drifted between reinstalls:\n--- first ---\n%s\n--- second ---\n%s", string(first), string(second))
	}

	// Second run should report the entries as kept, not added.
	if len(results) != 1 || results[0].Install == nil {
		t.Fatalf("unexpected second-install result: %+v", results)
	}
	if len(results[0].Install.HooksAdded) != 0 || len(results[0].Install.HooksKept) == 0 {
		t.Errorf("expected HooksKept on idempotent reinstall, got Added=%v Kept=%v",
			results[0].Install.HooksAdded, results[0].Install.HooksKept)
	}
}

// TestInstall_UsesTargetUserHomeNotProcessHome pins the wiring between
// resolveTargetUser and selectAdapters: the install must target the
// resolved user's home, not the calling process's $HOME. Plugging the
// mock home into a path that os.UserHomeDir would never return is the
// cheapest way to verify which path actually got used.
func TestInstall_UsesTargetUserHomeNotProcessHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-shape assertion is Unix-flavored")
	}
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := filepath.Join(t.TempDir(), "explicit-target-home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	if _, herr := Install(context.Background(), m, ""); herr != nil {
		t.Fatalf("install: %v", herr)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Errorf("install did not write under target-user home: %v", err)
	}
}
