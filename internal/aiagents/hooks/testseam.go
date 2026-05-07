package hooks

// SetResolveBinaryForTesting overrides the install/uninstall binary path
// resolver. Production code MUST NOT call this; it exists so tests in
// other packages (notably internal/aiagents/cli's smoke test) can pin a
// known binary path without depending on whatever os.Executable returns
// under `go test`. Returns a restore closure callers should defer.
//
// Not goroutine-safe — tests using it must not run in parallel.
func SetResolveBinaryForTesting(fn func() (string, error)) (restore func()) {
	prev := resolveBinary
	resolveBinary = fn
	return func() { resolveBinary = prev }
}
