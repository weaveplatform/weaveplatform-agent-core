package platform

import (
	"os"
	"runtime"
	"testing"
)

func TestHostDescribesThisMachine(t *testing.T) {
	info := Host()
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("Host() = %s/%s, want %s/%s", info.OS, info.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if hn, err := os.Hostname(); err == nil && info.Hostname != hn {
		t.Errorf("Hostname = %q, want %q", info.Hostname, hn)
	}
}

func TestPathsAreAllSet(t *testing.T) {
	p := Paths()
	for name, v := range map[string]string{
		"StateDir": p.StateDir, "LogDir": p.LogDir, "RunDir": p.RunDir, "StagingDir": p.StagingDir,
	} {
		if v == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
