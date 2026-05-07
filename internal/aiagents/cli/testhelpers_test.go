package cli

import (
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/aiagents/hooks"
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
// the previous values on cleanup.
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

const fakeBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

func okBinary() (string, error) { return fakeBinary, nil }

// withResolveBinary pins the orchestrator's binary-path resolver via the
// hooks package's test seam, restoring on cleanup.
func withResolveBinary(t *testing.T, fn func() (string, error)) {
	t.Helper()
	restore := hooks.SetResolveBinaryForTesting(fn)
	t.Cleanup(restore)
}

func newInstallMock(t *testing.T, home string) *executor.Mock {
	t.Helper()
	m := executor.NewMock()
	m.SetIsRoot(false)
	m.SetUsername("alice")
	m.SetHomeDir(home)
	return m
}
