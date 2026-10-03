package ipc

import (
	"errors"
	"net"
	"testing"
	"time"
)

// badAddr returns a pipe name already held by another listener: creating the
// first instance of a name that exists fails, which is a more dependable
// error than guessing which malformed names the kernel rejects.
func badAddr(t *testing.T) string {
	t.Helper()
	addr := testAddr(t)
	l, err := Listen(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return addr
}

// Named pipes carry no uid: access is the SDDL's job.
func checkPeerCred(t *testing.T, pc PeerCred) {
	t.Helper()
	if pc != (PeerCred{}) {
		t.Fatalf("peer cred = %+v, want zero on Windows", pc)
	}
}

func TestListenPipeSDDL(t *testing.T) {
	addr := testAddr(t)
	l, err := ListenPipeSDDL(addr, "D:(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := Dial(dialCtx(t), NetworkPipe, addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestListenRejectsTakenPipeName(t *testing.T) {
	if _, err := Listen(t.Context(), badAddr(t)); err == nil {
		t.Fatal("Listen took over a pipe name already in use")
	}
}

func TestPipeListenerCloseIsIdempotentAndFinal(t *testing.T) {
	l, err := Listen(t.Context(), testAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()
	// Close while an Accept waits: the case go-winio can wedge on.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > pipeCloseTimeout+time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("pending Accept succeeded after Close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pending Accept never returned")
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
}
