package hooks

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/aiagents/errlog"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// TargetUser identifies the user whose home `hooks install` should
// target. UID/GID are split out so chownToTarget doesn't have to
// re-parse them on each path.
type TargetUser struct {
	User    *user.User
	UID     int
	GID     int
	HomeDir string
}

// resolveTargetUser determines whose home directory the install should
// modify. It's the only sanctioned way for orchestration code to obtain
// a user — in particular, callers must NOT walk /etc/passwd or read
// $SUDO_USER directly.
//
// Behavior:
//   - non-root caller: returns the calling user; err==nil.
//   - root caller, console user resolved: returns the console user; err==nil.
//   - root caller, no console user resolved: appends an entry to the
//     errors log and returns *Error with code CodeTargetUserUnresolved.
//
// Callers translate the typed error into UX. The CLI presenter prints a
// friendly note and exits 0 (this isn't a hook-install error, just a
// no-op on a multi-user machine without an active session); the
// control-plane handler reports the same code to the backend.
func resolveTargetUser(exec executor.Executor) (TargetUser, *Error) {
	u, err := exec.LoggedInUser()
	if err != nil || u == nil {
		if exec.IsRoot() {
			detail := fmt.Sprintf("LoggedInUser returned err=%v", err)
			errlog.AppendError("install", "no_console_user", detail, "")
			return TargetUser{}, newError(CodeTargetUserUnresolved, detail)
		}
		return TargetUser{}, newError(CodeTargetUserUnresolved, "no logged-in user")
	}

	// Under root, executor.LoggedInUser falls back to the current user
	// (root) when it can't resolve the console user. Treat root-as-target
	// as "no console user found" — installing hooks into root's home
	// would write into a profile no human uses interactively.
	if exec.IsRoot() && (u.Username == "" || u.Username == "root") {
		const detail = "executor.LoggedInUser returned root under root caller"
		errlog.AppendError("install", "no_console_user", detail, "")
		return TargetUser{}, newError(CodeTargetUserUnresolved, detail)
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return TargetUser{
		User:    u,
		UID:     uid,
		GID:     gid,
		HomeDir: u.HomeDir,
	}, nil
}

// chownToTarget chowns each path to the target user's UID/GID. It's a
// best-effort helper: any individual chown failure is logged to the
// errors file and the loop continues — an unchown'd file is still a
// working install, just one the target user can't tidy up themselves.
//
// No-op on Windows (chown is a Unix concept) and when the caller is not
// root (chown to a different UID requires CAP_CHOWN). Empty paths in
// the slice are skipped silently so callers can pass `WriteResult.BackupPath`
// without first checking for "".
func chownToTarget(exec executor.Executor, paths []string, target TargetUser) {
	if !exec.IsRoot() {
		return
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if err := os.Chown(p, target.UID, target.GID); err != nil {
			errlog.AppendError("install", "chown_failed", fmt.Sprintf("chown %s to %d:%d: %v", p, target.UID, target.GID, err), "")
		}
	}
}
