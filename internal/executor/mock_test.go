package executor

import (
	"context"
	"testing"
)

func TestMock_IsAppleCLTStub(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		goos     string
		clt      bool
		path     string
		expected bool
	}{
		{"darwin /usr/bin/python3 without CLT → stub", "darwin", false, "/usr/bin/python3", true},
		{"darwin /usr/bin/pip3 without CLT → stub", "darwin", false, "/usr/bin/pip3", true},
		{"darwin /usr/bin/python3 with CLT → not stub", "darwin", true, "/usr/bin/python3", false},
		{"darwin /usr/bin/ssh without CLT → not stub (base system binary)", "darwin", false, "/usr/bin/ssh", false},
		{"darwin /usr/bin/ls without CLT → not stub (base system binary)", "darwin", false, "/usr/bin/ls", false},
		{"darwin /usr/local/bin → never a stub", "darwin", false, "/usr/local/bin/python3", false},
		{"darwin /opt/homebrew → never a stub", "darwin", false, "/opt/homebrew/bin/python3", false},
		{"linux /usr/bin/python3 without CLT flag → not a stub", "linux", false, "/usr/bin/python3", false},
		{"windows path → not a stub", "windows", false, `C:\Python\python.exe`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMock()
			m.SetGOOS(tc.goos)
			m.SetAppleCLTInstalled(tc.clt)
			if got := m.IsAppleCLTStub(ctx, tc.path); got != tc.expected {
				t.Errorf("IsAppleCLTStub(%q) on goos=%s clt=%v: got %v, want %v",
					tc.path, tc.goos, tc.clt, got, tc.expected)
			}
		})
	}
}
