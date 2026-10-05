package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	systemio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// A named pipe stands in for the virtio-serial port: both are kernel devices
// whose handles Windows serialises unless they are opened overlapped, and the
// pipe's server end plays the host.

// promptly bounds what must be immediate. The bug it guards against blocks
// forever, so the bound only has to be clearly short of that; the measured
// times are logged.
const promptly = time.Second

func pipeName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\weave-transport-%s-%d-%d`,
		strings.ReplaceAll(t.Name(), "/", "-"), os.Getpid(), time.Now().UnixNano())
}

// listenHost listens on a fresh pipe and returns its name and a channel that
// yields the host end once the guest has opened it.
func listenHost(t *testing.T, cfg *winio.PipeConfig) (string, <-chan net.Conn) {
	t.Helper()
	name := pipeName(t)
	l, err := winio.ListenPipe(name, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() }) //nolint:errcheck
	host := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(host)
			return
		}
		t.Cleanup(func() { c.Close() }) //nolint:errcheck
		host <- c
	}()
	return name, host
}

func acceptHost(t *testing.T, host <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c, ok := <-host:
		if !ok {
			t.Fatal("the host end was never accepted")
		}
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the host end was never accepted")
		return nil
	}
}

// devicePair opens the guest end overlapped and returns both ends.
func devicePair(t *testing.T, cfg *winio.PipeConfig) (*overlappedDevice, net.Conn) {
	t.Helper()
	name, host := listenHost(t, cfg)
	dev, err := openOverlapped(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() }) //nolint:errcheck
	return dev, acceptHost(t, host)
}

type ioResult struct {
	n   int
	err error
}

func pendingRead(r io.Reader, buf []byte) <-chan ioResult {
	ch := make(chan ioResult, 1)
	go func() {
		n, err := r.Read(buf)
		ch <- ioResult{n, err}
	}()
	return ch
}

func pendingWrite(w io.Writer, p []byte) <-chan ioResult {
	ch := make(chan ioResult, 1)
	go func() {
		n, err := w.Write(p)
		ch <- ioResult{n, err}
	}()
	return ch
}

// assertPending fails if op has already finished: the test is only meaningful
// while it is still in flight.
func assertPending(t *testing.T, what string, op <-chan ioResult) {
	t.Helper()
	select {
	case r := <-op:
		t.Fatalf("%s finished early: n=%d err=%v", what, r.n, r.err)
	case <-time.After(100 * time.Millisecond):
	}
}

func await(t *testing.T, what string, op <-chan ioResult, within time.Duration) ioResult {
	t.Helper()
	start := time.Now()
	select {
	case r := <-op:
		t.Logf("%s finished in %v", what, time.Since(start).Round(time.Microsecond))
		return r
	case <-time.After(within):
		t.Fatalf("%s did not finish within %v", what, within)
		return ioResult{}
	}
}

// The field bug: a write must leave while the read loop's read is pending.
func TestOverlappedWriteCompletesWhileReadPending(t *testing.T) {
	dev, host := devicePair(t, nil)

	buf := make([]byte, 4096)
	read := pendingRead(dev, buf)
	assertPending(t, "the read", read)

	msg := []byte("weave.presence.hello.result")
	w := await(t, "the write behind a pending read", pendingWrite(dev, msg), promptly)
	if w.err != nil || w.n != len(msg) {
		t.Fatalf("write: n=%d err=%v", w.n, w.err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(host, got); err != nil || string(got) != string(msg) {
		t.Fatalf("host read %q, %v", got, err)
	}

	// The read is still the same one, and returns what arrived even though it
	// asked for far more.
	if _, err := host.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	r := await(t, "the pending read", read, promptly)
	if r.err != nil || string(buf[:r.n]) != "abc" {
		t.Fatalf("read %q, %v", buf[:r.n], r.err)
	}
}

// The root cause, pinned: on a handle opened the way os.OpenFile opens one, a
// write waits for the pending read and is released only when the host sends
// something. If this ever starts failing, Windows or Go changed underneath,
// and the field traces this fix answers would need re-reading.
func TestSynchronousHandleSerialisesReadAndWrite(t *testing.T) {
	name, hostCh := listenHost(t, nil)
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() }) //nolint:errcheck
	host := acceptHost(t, hostCh)

	read := pendingRead(f, make([]byte, 64))
	assertPending(t, "the read", read)
	write := pendingWrite(f, []byte("reply"))
	assertPending(t, "the write on a synchronous handle", write)

	if _, err := host.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	await(t, "the read", read, promptly)
	if w := await(t, "the write, once the read let it go", write, promptly); w.err != nil {
		t.Fatal(w.err)
	}
}

func TestOverlappedCloseUnblocksPendingRead(t *testing.T) {
	dev, _ := devicePair(t, nil)
	read := pendingRead(dev, make([]byte, 64))
	assertPending(t, "the read", read)

	if err := dev.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if r := await(t, "the read after close", read, promptly); !errors.Is(r.err, os.ErrClosed) {
		t.Fatalf("a read ended by close should say so: %v", r.err)
	}
	if err := dev.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("second close: %v", err)
	}
	if _, err := dev.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := dev.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestOverlappedCloseUnblocksPendingWrite(t *testing.T) {
	// Small pipe buffers and a host that never reads: the write cannot finish.
	dev, _ := devicePair(t, &winio.PipeConfig{InputBufferSize: 512, OutputBufferSize: 512})
	write := pendingWrite(dev, make([]byte, 1<<20))
	assertPending(t, "the write", write)

	if err := dev.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if w := await(t, "the write after close", write, promptly); !errors.Is(w.err, os.ErrClosed) {
		t.Fatalf("a write ended by close should say so: %v", w.err)
	}
}

// The port going away ends the read with EOF, which ends the read loop and
// lets the device be reopened; a write to it fails rather than hanging.
func TestOverlappedFarEndGone(t *testing.T) {
	dev, host := devicePair(t, nil)
	read := pendingRead(dev, make([]byte, 64))
	assertPending(t, "the read", read)

	host.Close() //nolint:errcheck
	if r := await(t, "the read", read, promptly); !errors.Is(r.err, io.EOF) {
		t.Fatalf("read from a vanished host: %v", r.err)
	}
	if _, err := dev.Write([]byte("x")); err == nil || errors.Is(err, os.ErrClosed) {
		t.Fatalf("write to a vanished host: %v", err)
	}
}

// A cancellation nobody asked for is an I/O error, not a close.
func TestOverlappedCancelledWithoutClose(t *testing.T) {
	dev, _ := devicePair(t, nil)
	read := pendingRead(dev, make([]byte, 64))
	assertPending(t, "the read", read)

	if err := systemio.CancelIoEx(dev.h, nil); err != nil {
		t.Fatal(err)
	}
	r := await(t, "the cancelled read", read, promptly)
	if !errors.Is(r.err, errDeviceAborted) || errors.Is(r.err, os.ErrClosed) {
		t.Fatalf("cancelled read: %v", r.err)
	}
}

func TestOverlappedEmptyRead(t *testing.T) {
	dev, _ := devicePair(t, nil)
	if n, err := dev.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d, %v", n, err)
	}
}

func TestOverlappedEventFailures(t *testing.T) {
	// Any openable path will do: the failure comes before the device is used.
	name := filepath.Join(t.TempDir(), "vport")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	real := createIOEvent
	t.Cleanup(func() { createIOEvent = real })
	boom := errors.New("no event")
	for _, failOn := range []int{1, 2} {
		calls := 0
		createIOEvent = func() (foundation.HANDLE, error) {
			calls++
			if calls == failOn {
				return 0, boom
			}
			return real()
		}
		if _, err := openOverlapped(name); !errors.Is(err, boom) {
			t.Fatalf("event %d failing: %v", failOn, err)
		}
	}
}

// End to end, as the field saw it: the host says hello once and says nothing
// more, and the guest's answer must still arrive.
func TestHelloIsAnsweredOverAnOverlappedDevice(t *testing.T) {
	name, hostCh := listenHost(t, nil)
	rwc, err := openDevice(map[string]string{"device": name})
	if err != nil {
		t.Fatal(err)
	}
	host := acceptHost(t, hostCh)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.DiscardHandler)
	mux := &Mux{Log: log}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mux.Hypervisor = newHypervisorPeer(ctx, rwc, log, mux.deliver,
		newChannelAuth(log, writeKeyFile(t, pub)))
	t.Cleanup(func() { mux.Hypervisor.(*HypervisorPeer).Close() }) //nolint:errcheck
	in := mux.Receive(ctx, "weave")

	hostR, hostW := bufio.NewReader(host), bufio.NewWriter(host)
	send(t, hostW, "weave", hvchannel.PreAuthKind, map[string]string{"id": "h1"})
	select {
	case <-in:
	case <-time.After(5 * time.Second):
		t.Fatal("hello was not delivered")
	}
	start := time.Now()
	if err := mux.Hypervisor.Send(ctx, "weave",
		hvchannel.PreAuthKind+".result", []byte(`{"id":"h1"}`)); err != nil {
		t.Fatal(err)
	}
	got := readEnvelope(t, hostR)
	elapsed := time.Since(start)
	t.Logf("hello answered in %v", elapsed.Round(time.Microsecond))
	if got.Kind != hvchannel.PreAuthKind+".result" {
		t.Fatalf("read %q", got.Kind)
	}
	if elapsed > promptly {
		t.Fatalf("the hello reply took %v with no further host traffic", elapsed)
	}
}
