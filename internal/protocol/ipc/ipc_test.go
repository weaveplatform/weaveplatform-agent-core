package ipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// testAddr returns a fresh listen address for this platform. Socket dirs are
// short os.MkdirTemp paths: a t.TempDir() path under a long test name
// overruns the 104-byte sun_path limit on macOS.
func testAddr(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		return `\\.\pipe\weave-ipc-test-` + hex.EncodeToString(b[:])
	}
	dir, err := os.MkdirTemp("", "wipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func dialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestNetworkMatchesPlatform(t *testing.T) {
	want := NetworkUnix
	if runtime.GOOS == "windows" {
		want = NetworkPipe
	}
	if got := Network(); got != want {
		t.Fatalf("Network() = %q, want %q", got, want)
	}
}

func TestListenDialRoundTrip(t *testing.T) {
	addr := testAddr(t)
	l, err := Listen(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c) //nolint:errcheck
	}()

	c, err := Dial(dialCtx(t), Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestDialRefusesForeignNetwork(t *testing.T) {
	other := NetworkPipe
	if Network() == NetworkPipe {
		other = NetworkUnix
	}
	if _, err := Dial(dialCtx(t), other, testAddr(t)); err == nil {
		t.Fatalf("Dial accepted network %q on %s", other, runtime.GOOS)
	}
}

func TestGRPCClientSpeaksOverLocalTransport(t *testing.T) {
	addr := testAddr(t)
	l, err := Listen(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(l) //nolint:errcheck
	defer srv.Stop()

	conn, err := GRPCClient(Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resp, err := healthpb.NewHealthClient(conn).Check(dialCtx(t), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("status = %v", resp.GetStatus())
	}
}

func TestListenAuthorizedWithoutAuthorizerPassesThrough(t *testing.T) {
	addr := testAddr(t)
	l, err := ListenAuthorized(t.Context(), addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
		accepted <- err
	}()
	c, err := Dial(dialCtx(t), Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

// A rejected peer is closed and Accept goes on to the next connection rather
// than returning an error that would stop the server's accept loop.
func TestListenAuthorizedRejectsThenAccepts(t *testing.T) {
	addr := testAddr(t)
	var calls atomic.Int32
	creds := make(chan PeerCred, 2)
	l, err := ListenAuthorized(t.Context(), addr, func(pc PeerCred) error {
		creds <- pc
		if calls.Add(1) == 1 {
			return errors.New("not you")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	first, err := Dial(dialCtx(t), Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// The rejected connection is closed from the server side: a read sees
	// EOF (or a reset) rather than blocking.
	first.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection was not closed")
	}

	second, err := Dial(dialCtx(t), Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	c, ok := <-accepted
	if !ok {
		t.Fatal("Accept failed")
	}
	c.Close()
	if n := calls.Load(); n != 2 {
		t.Fatalf("authorizer called %d times, want 2", n)
	}
	checkPeerCred(t, <-creds)
}

func TestAuthorizedAcceptReportsListenerClose(t *testing.T) {
	l, err := ListenAuthorized(t.Context(), testAddr(t), func(PeerCred) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := l.Accept(); err == nil {
		t.Fatal("Accept on a closed listener succeeded")
	}
}

func TestListenAuthorizedPropagatesListenError(t *testing.T) {
	if _, err := ListenAuthorized(t.Context(), badAddr(t), nil); err == nil {
		t.Fatal("ListenAuthorized on an unusable address succeeded")
	}
}
