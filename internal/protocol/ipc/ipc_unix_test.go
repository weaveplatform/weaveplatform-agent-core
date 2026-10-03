//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func badAddr(t *testing.T) string {
	return filepath.Join(t.TempDir(), "no-such-dir", "s.sock")
}

func TestListenClearsStaleSocket(t *testing.T) {
	addr := testAddr(t)
	if err := os.WriteFile(addr, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(t.Context(), addr)
	if err != nil {
		t.Fatalf("stale file blocked Listen: %v", err)
	}
	defer l.Close()
	fi, err := os.Stat(addr)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want socket 0600", fi.Mode())
	}
}

func TestListenFailsWhenStalePathCannotBeRemoved(t *testing.T) {
	addr := testAddr(t)
	// A non-empty directory cannot be removed with os.Remove.
	if err := os.MkdirAll(filepath.Join(addr, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(t.Context(), addr); err == nil {
		t.Fatal("Listen succeeded over a non-empty directory")
	}
}

func TestListenFailsInMissingDirectory(t *testing.T) {
	if _, err := Listen(t.Context(), badAddr(t)); err == nil {
		t.Fatal("Listen succeeded in a missing directory")
	}
}

func TestPeerCredOnNonUnixConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if pc := peerCred(a); pc != (PeerCred{}) {
		t.Fatalf("peerCred(net.Pipe) = %+v, want zero", pc)
	}
}

// A UnixConn with no descriptor passes the type check but cannot be
// queried; the identity must come back empty.
func TestPeerCredWithoutDescriptor(t *testing.T) {
	if pc := peerCred(&net.UnixConn{}); pc != (PeerCred{}) {
		t.Fatalf("peerCred = %+v, want zero", pc)
	}
}
