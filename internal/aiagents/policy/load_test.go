package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// withCachePath redirects the loader to a temp file for the duration
// of the test. Cache override is process-wide state — these tests
// must not run in parallel.
func withCachePath(t *testing.T, path string) {
	t.Helper()
	prev := CachePathOverride()
	SetCachePathOverride(path)
	t.Cleanup(func() { SetCachePathOverride(prev) })
}

func TestLoadFallsBackToBuiltinWhenCacheMissing(t *testing.T) {
	withCachePath(t, filepath.Join(t.TempDir(), "absent.json"))
	pol, err := Load()
	if err != nil {
		t.Fatalf("Load returned error for missing file: %v", err)
	}
	if pol.Mode != Builtin().Mode {
		t.Fatalf("expected builtin fallback, got mode=%q", pol.Mode)
	}
}

func TestLoadReturnsCachedPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, CacheFileName)
	envelope := []byte(`{"etag":"sha256:abc","policy":{"version":1,"mode":"block","deny_command_patterns":["bun "]}}`)
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	withCachePath(t, path)

	pol, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pol.Mode != ModeBlock {
		t.Fatalf("mode=%q, want block — loader didn't unwrap envelope", pol.Mode)
	}
	if len(pol.DenyCommandPatterns) != 1 || pol.DenyCommandPatterns[0] != "bun " {
		t.Fatalf("deny_command_patterns lost: %+v", pol.DenyCommandPatterns)
	}
}

func TestLoadFallsBackOnMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withCachePath(t, path)

	pol, err := Load()
	if err == nil {
		t.Fatal("expected non-nil error for malformed cache")
	}
	if pol.Mode != Builtin().Mode {
		t.Fatalf("expected builtin fallback, got mode=%q", pol.Mode)
	}
}

func TestLoadFallsBackOnZeroVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFileName)
	// Envelope present but inner policy has version=0 — treat as
	// unwritten and fall back rather than feed a placeholder Policy
	// into the evaluator.
	if err := os.WriteFile(path, []byte(`{"etag":"sha256:x","policy":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withCachePath(t, path)

	pol, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pol.Mode != Builtin().Mode {
		t.Fatalf("expected builtin fallback, got mode=%q", pol.Mode)
	}
}

func TestCachePathHonorsOverride(t *testing.T) {
	withCachePath(t, "/tmp/explicit.json")
	got, err := CachePath()
	if err != nil {
		t.Fatalf("CachePath: %v", err)
	}
	if got != "/tmp/explicit.json" {
		t.Fatalf("got %q, want /tmp/explicit.json", got)
	}
}
