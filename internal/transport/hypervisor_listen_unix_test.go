package transport

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// unixPath is a short socket path: sun_path is 104 bytes on macOS, and a
// t.TempDir path alone can come close to that.
func unixPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func TestListenUnixRefusals(t *testing.T) {
	if _, err := listenUnix(""); !errors.Is(err, errChannelAttrs) {
		t.Fatalf("empty path: %v", err)
	}
	file := unixPath(t)
	if err := os.WriteFile(file, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(file); !errors.Is(err, errChannelAttrs) {
		t.Fatalf("regular file at the path: %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "mine" {
		t.Fatal("a non-socket at the path was touched")
	}
	if _, err := listenUnix(filepath.Join(unixPath(t), "missing-dir", "c.sock")); err == nil {
		t.Fatal("listened in a directory that does not exist")
	}
}

// A socket left behind by a previous core must not stop the next one binding.
func TestListenUnixReplacesAStaleSocket(t *testing.T) {
	path := unixPath(t)
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	// Abandon it the way a killed core would: the file stays, nobody listens.
	if ul, ok := old.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	old.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Skipf("platform removed the socket on close: %v", err)
	}
	l, err := listenUnix(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	defer l.Close()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o077 != 0 && runtimeIsUnix() {
		t.Fatalf("socket mode = %v, %v; want owner-only", fi.Mode(), err)
	}
}

func TestUnixListenerAcceptsAndCloses(t *testing.T) {
	path := unixPath(t)
	l, err := listenUnix(path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			_, err = c.Write([]byte("hi"))
			c.Close()
		}
		done <- err
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "hi" {
		t.Fatalf("read %q, %v", b, err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("accepted after close")
	}
}

// The container channel end to end: core listens, a host dials the socket,
// proves the key and delivers a frame.
func TestUnixChannelEndToEnd(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := unixPath(t)
	m := &Mux{Log: quietLog()}
	if err := m.ConnectHypervisor(
		t.Context(),
		map[string]string{"kind": unixKind, "path": path},
		writeKeyFile(t, pub),
	); err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	in := m.Receive(t.Context(), "weave.exec")

	var c net.Conn
	for deadline := time.Now().Add(5 * time.Second); ; {
		if c, err = net.Dial("unix", path); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	h := &host{r: bufio.NewReader(c), w: bufio.NewWriter(c)}
	if r := h.authenticate(t, priv); !r.OK {
		t.Fatalf("host refused: %s", r.Reason)
	}
	send(t, h.w, "weave.exec", "weave.exec.start", nil)
	select {
	case msg := <-in:
		if msg.Kind != "weave.exec.start" {
			t.Fatalf("delivered %q", msg.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("frame never delivered over the unix channel")
	}
}

func TestListenAnyRoutesByKind(t *testing.T) {
	if _, err := listenAny(
		map[string]string{"kind": unixKind},
		quietLog(),
	); !errors.Is(
		err,
		errChannelAttrs,
	) {
		t.Fatalf("unix without a path: %v", err)
	}
	// Anything else goes to the platform's hypervisor socket family, which
	// refuses a kind it does not serve.
	if _, err := listenAny(
		map[string]string{"kind": "no-such-kind", "port": "2010"},
		quietLog(),
	); !errors.Is(
		err,
		errChannelAttrs,
	) {
		t.Fatalf("unknown kind: %v", err)
	}
}

// A path the OS cannot even look up is reported, not mistaken for "absent".
func TestListenUnixUnreadablePath(t *testing.T) {
	if _, err := listenUnix("bad\x00path"); err == nil {
		t.Fatal("listened on a path containing NUL")
	}
}

// A stale socket core is not allowed to remove stops the bind with a reason.
func TestListenUnixStaleSocketItCannotRemove(t *testing.T) {
	if !runtimeIsUnix() || os.Geteuid() == 0 {
		t.Skip("needs unix directory permissions and a non-root user")
	}
	path := unixPath(t)
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := listenUnix(path); err == nil {
		t.Fatal("bound over a socket it could not remove")
	}
}

func runtimeIsUnix() bool { return filepath.Separator == '/' }
