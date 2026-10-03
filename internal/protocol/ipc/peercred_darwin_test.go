package ipc

import (
	"net"
	"os"
	"testing"
)

func checkPeerCred(t *testing.T, pc PeerCred) {
	t.Helper()
	if !pc.HasUID || pc.UID != uint32(os.Getuid()) {
		t.Fatalf("peer cred = %+v, want uid %d", pc, os.Getuid())
	}
	if pc.HasPID {
		t.Fatalf("LOCAL_PEERCRED reports no pid, got %+v", pc)
	}
}

// An unconnected socket has no peer: LOCAL_PEERCRED fails and the identity
// stays empty, which an Authorizer must treat as unknown.
func TestPeerCredWithoutPeer(t *testing.T) {
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: testAddr(t), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pc := peerCred(c); pc != (PeerCred{}) {
		t.Fatalf("peerCred(unconnected) = %+v, want zero", pc)
	}
}
