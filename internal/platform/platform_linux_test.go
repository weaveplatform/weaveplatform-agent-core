package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func withOSRelease(t *testing.T, path string) {
	t.Helper()
	old := osReleasePath
	osReleasePath = path
	t.Cleanup(func() { osReleasePath = old })
}

func TestFillParsesOSRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	doc := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nBUILD_ID=rolling\nID=ubuntu\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	withOSRelease(t, path)
	var info Info
	fill(&info)
	if info.Version != "24.04" || info.Build != "rolling" {
		t.Fatalf("got Version=%q Build=%q", info.Version, info.Build)
	}
}

// A host without os-release still describes itself: identity of the OS is
// best-effort, not a launch gate.
func TestFillWithoutOSRelease(t *testing.T) {
	withOSRelease(t, filepath.Join(t.TempDir(), "absent"))
	var info Info
	fill(&info)
	if info.Version != "" || info.Build != "" {
		t.Fatalf("invented a version: %+v", info)
	}
	if info.Hostname == "" {
		t.Error("hostname not filled")
	}
	if p := Paths(); p.StateDir != "/var/lib/weave" {
		t.Errorf("StateDir = %q", p.StateDir)
	}
}
