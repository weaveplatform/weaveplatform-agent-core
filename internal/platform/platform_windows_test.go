package platform

import (
	"path/filepath"
	"testing"
)

func TestItoa(t *testing.T) {
	for v, want := range map[uint64]string{0: "0", 7: "7", 10: "10", 26100: "26100", 18446744073709551615: "18446744073709551615"} {
		if got := itoa(v); got != want {
			t.Errorf("itoa(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestFillReadsWindowsVersion(t *testing.T) {
	var info Info
	fill(&info)
	if info.Version == "" || info.Build == "" {
		t.Fatalf("CurrentVersion registry values not read: %+v", info)
	}
}

func TestPathsHonourProgramData(t *testing.T) {
	t.Setenv("ProgramData", `D:\Data`)
	if got, want := Paths().LogDir, filepath.Join(`D:\Data`, "Weave", "logs"); got != want {
		t.Errorf("LogDir = %q, want %q", got, want)
	}
	t.Setenv("ProgramData", "")
	if got, want := Paths().StateDir, filepath.Join(`C:\ProgramData`, "Weave"); got != want {
		t.Errorf("StateDir = %q, want %q", got, want)
	}
}
