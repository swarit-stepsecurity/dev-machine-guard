package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
	"github.com/step-security/dev-machine-guard/internal/control"
)

func TestPolicyUpdate_NameIsCanonical(t *testing.T) {
	if got := (&PolicyUpdate{}).Name(); got != CmdPolicyUpdate {
		t.Fatalf("Name()=%q, want %q", got, CmdPolicyUpdate)
	}
	if CmdPolicyUpdate != "policy.update" {
		t.Fatalf("CmdPolicyUpdate must stay %q for backend wire compatibility, got %q", "policy.update", CmdPolicyUpdate)
	}
}

func TestPolicyUpdate_WritesEnvelopeToCache(t *testing.T) {
	dir := t.TempDir()
	h := NewPolicyUpdate(dir)
	args := json.RawMessage(`{
        "policy": {"version": 1, "mode": "block", "deny_tools": ["Bash"]},
        "etag": "sha256:abc123",
        "scope": "device"
    }`)

	out, err := h.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	res, ok := out.(policyUpdateResult)
	if !ok {
		t.Fatalf("expected policyUpdateResult, got %T", out)
	}
	if res.Etag != "sha256:abc123" {
		t.Fatalf("etag echo=%q", res.Etag)
	}

	body, err := os.ReadFile(filepath.Join(dir, policyCacheFileName))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var envelope struct {
		Etag   string        `json:"etag"`
		Policy policy.Policy `json:"policy"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.Etag != "sha256:abc123" {
		t.Fatalf("envelope.etag=%q", envelope.Etag)
	}
	if envelope.Policy.Mode != policy.ModeBlock {
		t.Fatalf("policy.mode=%q, want block", envelope.Policy.Mode)
	}
	if len(envelope.Policy.DenyTools) != 1 || envelope.Policy.DenyTools[0] != "Bash" {
		t.Fatalf("deny_tools roundtrip lost: %+v", envelope.Policy.DenyTools)
	}
}

func TestPolicyUpdate_RejectsMissingEtag(t *testing.T) {
	h := NewPolicyUpdate(t.TempDir())
	_, err := h.Execute(context.Background(), json.RawMessage(`{"policy":{"version":1,"mode":"audit"}}`))
	if err == nil {
		t.Fatal("expected error for missing etag")
	}
	var he *control.HandlerError
	if !errors.As(err, &he) || he.Code != control.CodeBadArgs {
		t.Fatalf("want CodeBadArgs, got %v", err)
	}
}

func TestPolicyUpdate_RejectsZeroVersion(t *testing.T) {
	h := NewPolicyUpdate(t.TempDir())
	_, err := h.Execute(context.Background(), json.RawMessage(`{"policy":{"mode":"audit"},"etag":"sha256:x"}`))
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	var he *control.HandlerError
	if !errors.As(err, &he) || he.Code != control.CodeBadArgs {
		t.Fatalf("want CodeBadArgs, got %v", err)
	}
}

func TestPolicyUpdate_RejectsBadJSON(t *testing.T) {
	h := NewPolicyUpdate(t.TempDir())
	_, err := h.Execute(context.Background(), json.RawMessage(`{"policy": "not-an-object"}`))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
	var he *control.HandlerError
	if !errors.As(err, &he) || he.Code != control.CodeBadArgs {
		t.Fatalf("want CodeBadArgs, got %v", err)
	}
}

func TestPolicyUpdate_RewriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	h := NewPolicyUpdate(dir)

	first := json.RawMessage(`{"policy":{"version":1,"mode":"audit"},"etag":"sha256:v1"}`)
	if _, err := h.Execute(context.Background(), first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	second := json.RawMessage(`{"policy":{"version":1,"mode":"block","deny_tools":["Edit"]},"etag":"sha256:v2"}`)
	if _, err := h.Execute(context.Background(), second); err != nil {
		t.Fatalf("second write: %v", err)
	}

	body, _ := os.ReadFile(filepath.Join(dir, policyCacheFileName))
	var envelope struct {
		Etag   string        `json:"etag"`
		Policy policy.Policy `json:"policy"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if envelope.Etag != "sha256:v2" || envelope.Policy.Mode != policy.ModeBlock {
		t.Fatalf("second write didn't replace first: %+v", envelope)
	}
}
