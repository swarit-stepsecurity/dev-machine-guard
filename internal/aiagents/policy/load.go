package policy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// CacheFileName is the on-disk cache file the daemon's `policy.update`
// handler writes and the `_hook` runtime reads. Lives under CacheDir().
const CacheFileName = "hook-policy.json"

// stepsecurityDirName is the per-user data directory dmg owns. Kept
// internal — callers should reach for CacheDir() so the resolution
// rule stays in one place.
const stepsecurityDirName = ".stepsecurity"

// cachePathOverride redirects loads to a test-controlled location.
// Production code never touches this; tests flip it via
// SetCachePathOverride / CachePathOverride. Process-wide state — tests
// that rely on it must not run in parallel.
var cachePathOverride string

// SetCachePathOverride redirects the policy cache to path. Pass "" to
// clear. Intended for tests; production code should not call this.
func SetCachePathOverride(path string) { cachePathOverride = path }

// CachePathOverride returns the current override, or "" when none is
// set. Pair with SetCachePathOverride in test cleanup hooks.
func CachePathOverride() string { return cachePathOverride }

// CacheDir returns ~/.stepsecurity (the directory containing
// CacheFileName). Empty + error if the home directory can't be
// resolved — caller decides how to fail.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, stepsecurityDirName), nil
}

// CachePath returns the absolute path of the policy cache file —
// either the test override or the resolved CacheDir() path.
func CachePath() (string, error) {
	if cachePathOverride != "" {
		return cachePathOverride, nil
	}
	dir, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, CacheFileName), nil
}

// cacheEnvelope is the on-disk wire shape the policy.update handler
// writes. Mirrors the args shape so the same struct round-trips.
type cacheEnvelope struct {
	Etag   string `json:"etag"`
	Policy Policy `json:"policy"`
}

// Load returns the policy the runtime should evaluate against:
//
//   - cache file present and parses + version is supported → that policy
//   - cache file missing                                   → Builtin()
//   - cache file present but unreadable / malformed        → Builtin(),
//     and a non-nil error so the caller can log
//
// Fail-open is the contract — a corrupt cache must never silently
// switch enforcement. The caller decides whether to surface the error.
func Load() (Policy, error) {
	path, err := CachePath()
	if err != nil {
		return Builtin(), err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Builtin(), nil
		}
		return Builtin(), err
	}
	var env cacheEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Builtin(), err
	}
	if env.Policy.Version == 0 {
		// Empty / placeholder envelope — treat the file as missing
		// rather than feed a zero-value Policy into the evaluator.
		return Builtin(), nil
	}
	return env.Policy, nil
}
