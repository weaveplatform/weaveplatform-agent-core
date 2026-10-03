package ipc

import (
	"os"
	"testing"
)

func checkPeerCred(t *testing.T, pc PeerCred) {
	t.Helper()
	if !pc.HasUID || pc.UID != uint32(os.Getuid()) {
		t.Fatalf("peer cred = %+v, want uid %d", pc, os.Getuid())
	}
	if !pc.HasPID || pc.PID != os.Getpid() {
		t.Fatalf("peer cred = %+v, want pid %d", pc, os.Getpid())
	}
}
