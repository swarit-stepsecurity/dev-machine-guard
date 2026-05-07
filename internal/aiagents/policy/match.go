package policy

import (
	"net/url"
	"path/filepath"
	"strings"
)

// matchTool reports whether toolName is in the case-insensitive
// denylist. Empty list ⇒ no match. Empty toolName ⇒ no match
// (Eval should never call us when there is nothing to compare).
func matchTool(deny []string, toolName string) bool {
	if toolName == "" || len(deny) == 0 {
		return false
	}
	for _, d := range deny {
		if strings.EqualFold(strings.TrimSpace(d), toolName) {
			return true
		}
	}
	return false
}

// matchCommandPattern reports whether any pattern occurs as a
// substring of cmd. Substring rather than regex by design — regex
// patterns are a known DoS surface (catastrophic backtracking) and
// substring covers the realistic block list ("rm -rf /", "curl | sh",
// "sudo", etc.).
//
// Patterns are case-sensitive: shell commands themselves are
// case-sensitive on every supported platform.
func matchCommandPattern(deny []string, cmd string) (string, bool) {
	if cmd == "" {
		return "", false
	}
	for _, p := range deny {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(cmd, p) {
			return p, true
		}
	}
	return "", false
}

// matchPath reports whether path matches any glob in the deny list.
// Paths are normalized to forward slashes and ~/ is expanded against
// the optional homeDir. "**" segments work like in shell globs:
// "**/.ssh/**" matches "/home/user/.ssh/id_rsa".
//
// Glob semantics:
//   - "*"  — matches any sequence of non-separator characters
//   - "?"  — matches any single non-separator character
//   - "**" — matches any sequence including separators (recursive)
//   - "[…]" — character class, as in filepath.Match
//
// Implementation note: Go's filepath.Match doesn't natively support
// "**", so we substitute it with a recursive walk against the
// remaining path. Bounded enough for our use case — patterns are
// short and paths are < 1KiB.
func matchPath(deny []string, path, homeDir string) (string, bool) {
	if path == "" {
		return "", false
	}
	norm := normalizePath(path, homeDir)
	for _, raw := range deny {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		pat := normalizePath(p, homeDir)
		if globMatch(pat, norm) {
			return raw, true
		}
	}
	return "", false
}

// matchHost reports whether the host parsed from rawURL is in the
// denylist. Two pattern shapes accepted:
//   - "evil.example"        — exact host match
//   - "*.evil.example"      — matches any sub-domain (NOT the apex
//     itself; admin should add both apex and wildcard if they want
//     both, mirroring DNS / TLS cert practice).
//
// Returns "" when the URL has no host or doesn't parse.
func matchHost(deny []string, rawURL string) (string, bool) {
	if rawURL == "" || len(deny) == 0 {
		return "", false
	}
	host := hostFromURL(rawURL)
	if host == "" {
		return "", false
	}
	host = strings.ToLower(host)
	for _, raw := range deny {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			suf := p[1:] // ".evil.example"
			if strings.HasSuffix(host, suf) && len(host) > len(suf) {
				return raw, true
			}
			continue
		}
		if host == p {
			return raw, true
		}
	}
	return "", false
}

// matchMCPServer reports whether toolName carries an mcp__<server>__…
// prefix and that server is in the denylist. Tool names without the
// MCP prefix never match.
func matchMCPServer(deny []string, toolName string) (string, bool) {
	if toolName == "" || len(deny) == 0 {
		return "", false
	}
	const prefix = "mcp__"
	low := strings.ToLower(toolName)
	if !strings.HasPrefix(low, prefix) {
		return "", false
	}
	rest := toolName[len(prefix):]
	server := rest
	if i := strings.Index(rest, "__"); i >= 0 {
		server = rest[:i]
	}
	if server == "" {
		return "", false
	}
	for _, raw := range deny {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if strings.EqualFold(p, server) {
			return server, true
		}
	}
	return "", false
}

// matchCWDAllowlist returns ("",true) when cwd is permitted (i.e.,
// allowlist is empty OR cwd is under at least one prefix).
// Returns (allowlist-summary, false) when cwd is OUTSIDE every prefix.
//
// Prefix semantics: an entry like "/home/alice/projects" matches any
// cwd that begins with "/home/alice/projects" followed by "/" or
// end-of-string. Trailing slash on the prefix is normalized away.
// "~/" is expanded against homeDir.
func matchCWDAllowlist(allow []string, cwd, homeDir string) (string, bool) {
	if len(allow) == 0 {
		return "", true
	}
	if cwd == "" {
		// No CWD on the event — treat as "outside all prefixes" rather
		// than "matches everything", since the allowlist is meant to
		// ring-fence specific dirs.
		return strings.Join(allow, ", "), false
	}
	c := normalizePath(cwd, homeDir)
	for _, raw := range allow {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		prefix := strings.TrimRight(normalizePath(p, homeDir), "/")
		if c == prefix || strings.HasPrefix(c, prefix+"/") {
			return "", true
		}
	}
	return strings.Join(allow, ", "), false
}

// hostFromURL extracts the lowercased hostname (no port) from a URL
// string. Empty when parsing fails or the URL has no host. Bare
// hostnames without scheme also work — we synthesize "https://".
func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Try again with a synthesized scheme so plain "evil.com/x"
		// still parses with a Host. Only do this once to avoid
		// infinite recursion if the synthesis ALSO fails.
		if !strings.Contains(raw, "://") {
			u, err = url.Parse("https://" + raw)
			if err != nil || u.Host == "" {
				return ""
			}
		} else {
			return ""
		}
	}
	host := u.Hostname()
	return host
}

// normalizePath canonicalizes a path or pattern: forward slashes,
// "~/…" expanded against homeDir, redundant slashes collapsed. Does
// NOT resolve symlinks or filepath.Clean a pattern (which would eat
// "**").
func normalizePath(p, homeDir string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	if homeDir != "" {
		switch {
		case p == "~":
			p = homeDir
		case strings.HasPrefix(p, "~/"):
			p = strings.TrimRight(filepath.ToSlash(homeDir), "/") + "/" + p[2:]
		}
	}
	// Collapse "//" sequences, but leave the rest alone — filepath.Clean
	// would canonicalize "**/" away, breaking our recursive glob.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// globMatch reports whether path matches pattern with "**" support.
// Algorithm:
//   - Split pattern on "**" boundaries; each piece is a filepath.Match
//     compatible glob with "*", "?", "[…]" semantics.
//   - The pieces must appear in order in path; "**" between them
//     consumes any number of characters (including separators).
//   - Anchored at both ends: an empty leading piece matches a leading
//     "/" / start, an empty trailing piece matches anywhere to the
//     end.
//
// Example: pattern "**/.ssh/**" matches "/home/alice/.ssh/id_rsa".
func globMatch(pattern, path string) bool {
	pattern = filepath.ToSlash(pattern)
	if !strings.Contains(pattern, "**") {
		// Fast path: plain filepath.Match.
		ok, err := filepath.Match(pattern, path)
		return err == nil && ok
	}
	parts := strings.Split(pattern, "**")
	// First piece must match at the start.
	first := parts[0]
	if first != "" {
		if !matchAtStart(first, path) {
			return false
		}
		path = path[len(first):]
		// If first ended without a separator, also strip up to the
		// next separator so "**" consumes intra-segment chars.
	}
	// Middle pieces and last must each appear in order.
	for i := 1; i < len(parts); i++ {
		piece := parts[i]
		if piece == "" {
			// trailing "**" — anything is fine.
			return true
		}
		// Find the earliest position where piece matches a substring.
		idx := -1
		for j := 0; j+len(piece) <= len(path); j++ {
			if matchAtStart(piece, path[j:]) {
				idx = j
				break
			}
		}
		if idx < 0 {
			return false
		}
		path = path[idx+pieceConsumed(piece, path[idx:]):]
	}
	return path == "" || strings.HasPrefix(path, "/")
}

// matchAtStart reports whether the literal-glob prefix matches the
// beginning of path. "literal-glob" = no "**", but "*" / "?" / "[…]"
// allowed.
func matchAtStart(prefix, path string) bool {
	if prefix == "" {
		return true
	}
	// filepath.Match needs the lengths to be commensurate — we use
	// it on the slice of path covering the prefix's expanded length.
	// Easiest correct approach: try matching prefix against
	// progressively longer prefixes of path until one wins or we
	// exhaust the input.
	for n := len(prefix); n <= len(path); n++ {
		ok, err := filepath.Match(prefix, path[:n])
		if err == nil && ok {
			return true
		}
	}
	return false
}

// pieceConsumed returns how many characters of the path were "used"
// by piece. Approximation: piece's literal length, plus any glob
// expansion. We re-walk to find the actual match length.
func pieceConsumed(piece, path string) int {
	for n := 1; n <= len(path); n++ {
		ok, err := filepath.Match(piece, path[:n])
		if err == nil && ok {
			return n
		}
	}
	return len(piece)
}
