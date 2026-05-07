package handlers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/aiagents/hooks"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/control"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

const fakeBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

func okBinary() (string, error) { return fakeBinary, nil }

// withErrorLog redirects the errors log to a temp path. Same shape as
// the helpers in cli/hooks tests; duplicated here so this package owns
// its own test scaffolding.
func withErrorLog(t *testing.T) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "errors.jsonl")
	prev := errlog.PathOverride()
	errlog.SetPathOverride(tmp)
	t.Cleanup(func() { errlog.SetPathOverride(prev) })
}

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

func withResolveBinary(t *testing.T, fn func() (string, error)) {
	t.Helper()
	t.Cleanup(hooks.SetResolveBinaryForTesting(fn))
}

func newMockUser(t *testing.T) (*executor.Mock, string) {
	t.Helper()
	home := t.TempDir()
	m := executor.NewMock()
	m.SetIsRoot(false)
	m.SetUsername("alice")
	m.SetHomeDir(home)
	return m, home
}

func TestHooksInstall_NameAndPanicOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil executor")
		}
	}()
	NewHooksInstall(nil)
}

func TestHooksInstall_RoundTripReturnsTypedResults(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m, _ := newMockUser(t)
	m.SetPath("claude", "/usr/local/bin/claude")

	h := NewHooksInstall(m)
	args := json.RawMessage(`{}`)
	out, err := h.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	results, ok := out.([]hooks.AgentResult)
	if !ok {
		t.Fatalf("execute returned %T, want []hooks.AgentResult", out)
	}
	if len(results) != 1 || results[0].Agent != "claude-code" || results[0].Status != hooks.StatusOK {
		t.Errorf("unexpected: %+v", results)
	}
}

func TestHooksInstall_EmptyArgsAcceptedAsDefault(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m, _ := newMockUser(t) // no SetPath, so no agents detected
	h := NewHooksInstall(m)

	// Try every shape backends might produce: nil, "", "null".
	for _, args := range []json.RawMessage{nil, json.RawMessage(""), json.RawMessage("null")} {
		out, err := h.Execute(context.Background(), args)
		if err != nil {
			t.Fatalf("args=%q execute err=%v", string(args), err)
		}
		if results := out.([]hooks.AgentResult); len(results) != 0 {
			t.Errorf("args=%q expected empty results, got %+v", string(args), results)
		}
	}
}

func TestHooksInstall_BadArgsReturnsCodeBadArgs(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m, _ := newMockUser(t)
	h := NewHooksInstall(m)

	_, err := h.Execute(context.Background(), json.RawMessage(`["not", "an", "object"]`))
	if err == nil {
		t.Fatal("expected error on malformed args")
	}
	var he *control.HandlerError
	if !errorsAs(err, &he) {
		t.Fatalf("error not *HandlerError: %T %v", err, err)
	}
	if he.Code != control.CodeBadArgs {
		t.Errorf("Code=%q, want %q", he.Code, control.CodeBadArgs)
	}
}

func TestHooksInstall_NoEnterpriseConfigMapsToContractCode(t *testing.T) {
	// Leave config as default placeholders.
	withErrorLog(t)
	withResolveBinary(t, okBinary)
	m, _ := newMockUser(t)

	h := NewHooksInstall(m)
	_, err := h.Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var he *control.HandlerError
	if !errorsAs(err, &he) {
		t.Fatalf("not *HandlerError: %T %v", err, err)
	}
	if he.Code != string(hooks.CodeEnterpriseConfigMissing) {
		t.Errorf("Code=%q, want %q", he.Code, hooks.CodeEnterpriseConfigMissing)
	}
	// And the wrapped *hooks.Error must still be reachable via errors.As.
	if hh := errorsAsHooks(err); hh == nil || hh.Code != hooks.CodeEnterpriseConfigMissing {
		t.Errorf("wrapped *hooks.Error not preserved: %v", err)
	}
}

func TestHooksInstall_UnsupportedAgentMapsToBadArgs(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m, _ := newMockUser(t)
	h := NewHooksInstall(m)

	_, err := h.Execute(context.Background(), json.RawMessage(`{"agent":"cursor"}`))
	if err == nil {
		t.Fatal("expected error on unsupported agent")
	}
	var he *control.HandlerError
	if !errorsAs(err, &he) {
		t.Fatalf("not *HandlerError: %T %v", err, err)
	}
	// Per contract: caller-provided bad name → bad_args, not unsupported_agent.
	if he.Code != control.CodeBadArgs {
		t.Errorf("Code=%q, want %q", he.Code, control.CodeBadArgs)
	}
}

// TestHooksUninstall_RoundTripReturnsTypedResults is the symmetric
// check for the uninstall handler. Seeds a fresh install via the
// install handler so the test does not depend on the package-internal
// hooks.Install path having any side-effects we don't observe via the
// public API.
func TestHooksUninstall_RoundTripReturnsTypedResults(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m, _ := newMockUser(t)
	m.SetPath("claude", "/usr/local/bin/claude")

	if _, err := NewHooksInstall(m).Execute(context.Background(), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("seed install: %v", err)
	}

	out, err := NewHooksUninstall(m).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	results := out.([]hooks.AgentResult)
	if len(results) != 1 || results[0].Agent != "claude-code" {
		t.Fatalf("unexpected: %+v", results)
	}
	if results[0].Uninstall == nil || len(results[0].Uninstall.HooksRemoved) == 0 {
		t.Errorf("expected HooksRemoved set on uninstall result, got %+v", results[0])
	}
}

// errorsAs is the conventional wrapper used by handler tests so each
// call site doesn't import errors just for As. Defers to the stdlib.
func errorsAs(err error, target any) bool {
	if err == nil {
		return false
	}
	switch tgt := target.(type) {
	case **control.HandlerError:
		var h *control.HandlerError
		if asErr(err, &h) {
			*tgt = h
			return true
		}
	}
	return false
}

func asErr(err error, target **control.HandlerError) bool {
	for {
		if h, ok := err.(*control.HandlerError); ok {
			*target = h
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
	}
}
