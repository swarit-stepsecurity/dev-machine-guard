// Package errlog owns the per-user errors log
// (~/.stepsecurity/ai-agent-hook-errors.jsonl) shared by every AI-agent
// subsystem: the hooks install/uninstall handlers, the hot-path runtime,
// and the new control-plane handlers. The log is best-effort and
// fail-open — any failure to write is silently dropped so logging cannot
// block the caller.
//
// This package was extracted from internal/aiagents/cli when the
// install/uninstall orchestration moved into internal/aiagents/hooks; both
// packages need the appender, so it lives one level up.
package errlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// ErrorLogFilename is the basename of the per-user errors log. It lives
// directly under ~/.stepsecurity/.
const ErrorLogFilename = "ai-agent-hook-errors.jsonl"

// MaxErrorLogBytes triggers a truncate-and-restart before each append.
// At 5 MiB, individual entries < 4 KiB remain atomic on POSIX
// `O_APPEND` writes without advisory locks.
const MaxErrorLogBytes = 5 * 1024 * 1024

const (
	errorLogFileMode      os.FileMode = 0o600
	errorLogParentDirMode os.FileMode = 0o700
)

// ErrorEntry is the JSONL shape of a single line in the errors log.
// Field tags are short to keep the file compact when something goes
// wrong on the hot path; eventID is omitted when not correlated to an
// upload.
type ErrorEntry struct {
	Timestamp string `json:"ts"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	EventID   string `json:"event_id,omitempty"`
}

// errorLogPathOverride redirects writes to a test-controlled location.
// "" means "use the default ~/.stepsecurity/<filename> path." Tests
// across multiple packages need to flip this, so it is mutated only
// through SetPathOverride / PathOverride; the variable itself stays
// unexported. Tests must restore on cleanup since this is process-wide
// state with no synchronization.
var errorLogPathOverride string

// SetPathOverride redirects the errors log to path. Pass "" to clear
// the override and fall back to ~/.stepsecurity/<filename>. Test-only;
// production code must not call this. Not goroutine-safe — tests using
// it must not run in parallel.
func SetPathOverride(path string) { errorLogPathOverride = path }

// PathOverride returns the current override, or "" if none is set.
// Pair with SetPathOverride to save/restore in test cleanup hooks.
func PathOverride() string { return errorLogPathOverride }

// AppendError writes a single JSONL entry to the errors log. The call
// is best-effort: any failure (no $HOME, mkdir denied, marshal error,
// open denied, partial write) is silently dropped — the hot path's
// allow response must never be blocked by logging.
//
// The message is run through redact.String before being written to
// disk so a stray secret in an error message never lands in the
// on-disk log.
func AppendError(stage, code, message, eventID string) {
	path := errorLogPath()
	if path == "" {
		return
	}

	entry := ErrorEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Stage:     stage,
		Code:      code,
		Message:   redact.String(message),
		EventID:   eventID,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), errorLogParentDirMode); err != nil {
		return
	}

	// Truncate-and-restart at the size cap. We stat first to avoid the
	// truncate when the file is small (the common case). Failure here is
	// non-fatal: if we can't stat or truncate, fall through to append
	// anyway so the entry isn't lost on a non-cap-related stat error.
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > MaxErrorLogBytes {
		_ = os.Truncate(path, 0)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, errorLogFileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}

// ErrorLogPath returns the absolute path of the errors log for the
// current user (or the test override). Exposed for diagnostics paths
// that want to surface the location to the user.
func ErrorLogPath() string {
	return errorLogPath()
}

func errorLogPath() string {
	if errorLogPathOverride != "" {
		return errorLogPathOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".stepsecurity", ErrorLogFilename)
}

