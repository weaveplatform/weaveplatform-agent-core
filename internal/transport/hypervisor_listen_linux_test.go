package transport

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestListenSocketRefusesBadAttrs(t *testing.T) {
	for _, attrs := range []map[string]string{
		{"kind": "hvsocket", "port": "2010"},
		{"kind": "vsock", "port": "nope"},
	} {
		if _, err := listenSocket(attrs, quietLog()); !errors.Is(err, errChannelAttrs) {
			t.Errorf("listenSocket(%v) = %v", attrs, err)
		}
	}
}

// vsockPort is far from anything a real guest service would use.
const vsockPort = 52011

// listenOrSkip listens for real, or skips when AF_VSOCK is unavailable: a
// kernel without the transport (EAFNOSUPPORT, ENODEV, EADDRNOTAVAIL) or a
// container whose seccomp profile refuses the family (EPERM, EACCES).
func listenOrSkip(t *testing.T, port uint32) connListener {
	t.Helper()
	l, err := listenSocket(map[string]string{"kind": "vsock", "port": itoa(port)}, quietLog())
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EADDRNOTAVAIL) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) {
		t.Skipf("AF_VSOCK unavailable on this kernel: %v", err)
	}
	if err != nil {
		t.Fatalf("listenSocket: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func itoa(n uint32) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			return string(b)
		}
	}
}

// Close must unblock a pending Accept: it is how core stops the accept loop.
func TestVsockCloseUnblocksAccept(t *testing.T) {
	l := listenOrSkip(t, vsockPort)
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
}

func TestVsockPortInUse(t *testing.T) {
	listenOrSkip(t, vsockPort+1)
	if l, err := listenVsock(unix.VMADDR_CID_ANY, vsockPort+1); err == nil {
		l.Close()
		t.Fatal("bound a port that is already bound")
	}
}

// End to end over vsock loopback (CID 1), which needs the vsock_loopback
// module; skipped without it. Proves an accepted connection is a working,
// closable byte stream — the read loop needs nothing more.
func TestVsockLoopback(t *testing.T) {
	l := listenOrSkip(t, vsockPort+2)
	dialed := make(chan *os.File, 1)
	dialErr := make(chan error, 1)
	go func() {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Connect(
				fd,
				&unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: vsockPort + 2},
			)
		}
		if err != nil {
			dialErr <- err
			return
		}
		dialed <- os.NewFile(uintptr(fd), "dial")
	}()
	var client *os.File
	select {
	case err := <-dialErr:
		t.Skipf("no vsock loopback (vsock_loopback not loaded?): %v", err)
	case client = <-dialed:
	case <-time.After(5 * time.Second):
		t.Skip("vsock loopback connect did not complete")
	}
	defer client.Close()

	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q, %v", buf, err)
	}
	// Closing from another goroutine ends a blocked read: that is how a
	// replaced host's read loop stops.
	readErr := make(chan error, 1)
	go func() { _, err := conn.Read(buf); readErr <- err }()
	time.Sleep(20 * time.Millisecond)
	conn.Close()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read succeeded on a closed connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

// The whole socket channel over real AF_VSOCK loopback: core listens, a host
// dials and authenticates, and a module frame crosses. Skipped where vsock
// loopback is unavailable; the same logic runs everywhere over pipes in
// hypervisor_listen_test.go.
func TestVsockChannelEndToEnd(t *testing.T) {
	listenOrSkip(t, vsockPort+3).Close() // skip early if the family is missing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &Mux{Log: quietLog()}
	if err := m.ConnectHypervisor(
		t.Context(),
		map[string]string{"kind": "vsock", "port": itoa(vsockPort + 3)},
		writeKeyFile(t, pub),
	); err != nil {
		t.Fatalf("ConnectHypervisor: %v", err)
	}
	in := m.Receive(t.Context(), "weave")

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("vsock dial: %v", err)
	}
	if err := unix.Connect(
		fd,
		&unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: vsockPort + 3},
	); err != nil {
		unix.Close(fd)
		t.Skipf("no vsock loopback (vsock_loopback not loaded?): %v", err)
	}
	f := os.NewFile(uintptr(fd), "host")
	defer f.Close()
	h := &host{r: bufio.NewReader(f), w: bufio.NewWriter(f)}
	if r := h.authenticate(t, priv); !r.OK {
		t.Fatalf("host refused: %s", r.Reason)
	}
	send(t, h.w, "weave", "weave.presence.hello", nil)
	select {
	case msg := <-in:
		if msg.Kind != "weave.presence.hello" {
			t.Fatalf("delivered %q", msg.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("frame never delivered over vsock")
	}
}

// The listener plumbing is family-independent; AF_UNIX runs it on any Linux
// kernel, including containers whose seccomp profile refuses AF_VSOCK.
func unixStream(t *testing.T) (*streamListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	l, err := listenStream(unix.AF_UNIX, &unix.SockaddrUnix{Name: path})
	if err != nil {
		t.Fatalf("listenStream: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestStreamListenerOverUnix(t *testing.T) {
	l, path := unixStream(t)
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("client read %q, %v", buf, err)
	}
	readErr := make(chan error, 1)
	go func() { _, err := conn.Read(buf); readErr <- err }()
	time.Sleep(20 * time.Millisecond)
	conn.Close()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read succeeded on a closed connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Read")
	}

	acceptErr := make(chan error, 1)
	go func() { _, err := l.Accept(); acceptErr <- err }()
	time.Sleep(20 * time.Millisecond)
	l.Close()
	select {
	case err := <-acceptErr:
		if err == nil {
			t.Fatal("Accept succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
}

func TestListenStreamFailures(t *testing.T) {
	if _, err := listenStream(
		-1,
		&unix.SockaddrUnix{Name: "x"},
	); err == nil ||
		!strings.Contains(err.Error(), "socket") {
		t.Fatalf("socket of a bad family = %v", err)
	}
	_, path := unixStream(t)
	if _, err := listenStream(
		unix.AF_UNIX,
		&unix.SockaddrUnix{Name: path},
	); err == nil ||
		!strings.Contains(err.Error(), "bind") {
		t.Fatalf("bind of a bound path = %v", err)
	}
}
