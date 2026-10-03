package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDeviceWindowsPrefersProbedPath(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "vport")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rwc, err := openDevice(map[string]string{"device": dev})
	if err != nil {
		t.Fatalf("openDevice: %v", err)
	}
	rwc.Close() //nolint:errcheck
}

func TestOpenDeviceWindowsNothingOpenable(t *testing.T) {
	rwc, err := openDevice(map[string]string{"device": filepath.Join(t.TempDir(), "absent")})
	if err == nil {
		// A runner that happens to expose COM2 opens the fallback; that is
		// the documented behaviour, not a failure.
		rwc.Close() //nolint:errcheck
		t.Skip("a fallback device is present on this host")
	}
	if !strings.Contains(err.Error(), "no openable hypervisor device") ||
		!strings.Contains(err.Error(), "absent") {
		t.Fatalf("error should list the candidates tried: %v", err)
	}
}

func TestDefaultChannelKeyPathWindows(t *testing.T) {
	t.Setenv("ProgramData", `D:\PD`)
	if got := DefaultChannelKeyPath(); got != `D:\PD\weave\channel.pub` {
		t.Fatalf("with ProgramData: %q", got)
	}
	t.Setenv("ProgramData", "")
	if got := DefaultChannelKeyPath(); got != `C:\ProgramData\weave\channel.pub` {
		t.Fatalf("without ProgramData: %q", got)
	}
}
