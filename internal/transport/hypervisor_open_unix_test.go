//go:build unix

package transport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDeviceUnix(t *testing.T) {
	if _, err := openDevice(
		map[string]string{},
	); err == nil ||
		!strings.Contains(err.Error(), "no hypervisor device") {
		t.Fatalf("no device attr: %v", err)
	}
	if _, err := openDevice(
		map[string]string{"device": filepath.Join(t.TempDir(), "absent")},
	); err == nil {
		t.Fatal("opened a device that does not exist")
	}

	// A virtio-ports node is a plain character device: opened as-is.
	plain := filepath.Join(t.TempDir(), "vport")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rwc, err := openDevice(map[string]string{"device": plain})
	if err != nil {
		t.Fatal(err)
	}
	rwc.Close() //nolint:errcheck
}

// A pty master stands in for the macOS /dev/cu.* channel: it is a terminal,
// so openDevice must switch it to raw mode before framing runs over it.
func TestOpenDeviceTerminalGoesRaw(t *testing.T) {
	if f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0); err != nil {
		t.Skipf("no pty available: %v", err)
	} else {
		f.Close() //nolint:errcheck
	}
	rwc, err := openDevice(map[string]string{"device": "/dev/ptmx"})
	if err != nil {
		t.Fatalf("openDevice(pty): %v", err)
	}
	rwc.Close() //nolint:errcheck
}

func TestConnectHypervisorNoDevice(t *testing.T) {
	m := &Mux{Log: quietLog()}
	err := m.ConnectHypervisor(context.Background(), map[string]string{}, "")
	if err == nil || !strings.Contains(err.Error(), "opening hypervisor channel") {
		t.Fatalf("ConnectHypervisor without a device: %v", err)
	}
	if m.Hypervisor != nil {
		t.Fatal("peer wired despite the open failure")
	}
}
