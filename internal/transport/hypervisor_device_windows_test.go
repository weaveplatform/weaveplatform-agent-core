package transport

import (
	"bufio"
	"bytes"
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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
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
// yields each host end as the guest opens it.
func listenHost(t *testing.T, cfg *winio.PipeConfig) (string, <-chan net.Conn) {
	t.Helper()
	name := pipeName(t)
	l, err := winio.ListenPipe(name, cfg)
	if err != nil {
		t.Fatal(err)
	}
	host := make(chan net.Conn, 4)
	done := make(chan struct{})
	var mu sync.Mutex
	var conns []net.Conn
	// Bounded: go-winio's Close can wedge when it races a pending Accept, and
	// a cleanup that waits forever hangs the whole package.
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range conns {
			c.Close() //nolint:errcheck
		}
		mu.Unlock()
		go l.Close() //nolint:errcheck
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the host pipe listener did not stop")
		}
	})
	go func() {
		defer close(done)
		defer close(host)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			select {
			case host <- c:
			default: // nobody is waiting for it; cleanup closes it
			}
		}
	}()
	return name, host
}

// retryBusy retries open while the pipe has no listening instance yet: go-winio
// only creates one once its accept loop is running, and until then an open
// fails with ERROR_PIPE_BUSY, which a real port never returns.
func retryBusy[T any](t *testing.T, open func() (T, error)) T {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, err := open()
		if err == nil {
			return v
		}
		if !errors.Is(err, syscall.Errno(foundation.ERROR_PIPE_BUSY)) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	dev := retryBusy(t, func() (*overlappedDevice, error) { return openOverlapped(name) })
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

// A frame far larger than one device write goes out whole, in order, while
// the read loop's read stays pending, and the read still gets what the host
// sends afterwards.
func TestOverlappedLargeFrameWhileReadPending(t *testing.T) {
	dev, host := devicePair(t, nil)
	buf := make([]byte, 4096)
	read := pendingRead(dev, buf)
	assertPending(t, "the read", read)

	payload := make([]byte, 64<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	go func() {
		b, err := hvchannel.ReadFrame(host)
		if err != nil {
			t.Error(err)
		}
		got <- b
	}()
	w := await(t, "the 64 KiB frame", pendingWrite(dev, rawFrame(t, payload)), 10*time.Second)
	if w.err != nil {
		t.Fatalf("write: %v", w.err)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, payload) {
			t.Fatalf("host read %d bytes, not the %d written", len(b), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host never read the frame")
	}
	if _, err := host.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if r := await(t, "the pending read", read, promptly); r.err != nil || string(buf[:r.n]) != "after" {
		t.Fatalf("read %q, %v", buf[:r.n], r.err)
	}
}

// A hundred frames of mixed sizes each way at once, as a busy exec session
// streams output while the host sends input: every frame arrives, intact and
// in order, on both sides.
func TestOverlappedMixedBurstBothWays(t *testing.T) {
	dev, host := devicePair(t, nil)
	const frames = 100
	sizes := make([]int, frames)
	for i := range sizes {
		sizes[i] = []int{0, 1, 17, 512, 4095, 4096, 4097, 9000, 20000, 65536}[i%10]
	}
	payload := func(dir, i int) []byte {
		b := make([]byte, sizes[i])
		for j := range b {
			b[j] = byte(dir*31 + i + j)
		}
		return b
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	send := func(w io.Writer, dir int) {
		defer wg.Done()
		bw := bufio.NewWriter(w)
		for i := range frames {
			if err := hvchannel.WriteFrame(bw, payload(dir, i)); err != nil {
				errs <- fmt.Errorf("dir %d frame %d: %w", dir, i, err)
				return
			}
			if err := bw.Flush(); err != nil {
				errs <- fmt.Errorf("dir %d frame %d flush: %w", dir, i, err)
				return
			}
		}
	}
	recv := func(r io.Reader, dir int) {
		defer wg.Done()
		br := bufio.NewReader(r)
		for i := range frames {
			b, err := hvchannel.ReadFrame(br)
			if err != nil {
				errs <- fmt.Errorf("dir %d frame %d: %w", dir, i, err)
				return
			}
			if !bytes.Equal(b, payload(dir, i)) {
				errs <- fmt.Errorf("dir %d frame %d: %d bytes, not the %d sent", dir, i, len(b), sizes[i])
				return
			}
		}
	}
	wg.Add(4)
	go send(dev, 0)
	go recv(host, 0)
	go send(host, 1)
	go recv(dev, 1)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the burst did not complete")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Every WriteFile is at most maxDeviceWrite, so a large write never asks the
// driver for more descriptors than a small queue has.
func TestOverlappedWriteIsChunked(t *testing.T) {
	dev, host := devicePair(t, nil)
	var mu sync.Mutex
	var lens []int
	stubWriteFile(t, func(h foundation.HANDLE, p []byte, n *uint32, ov *systemio.OVERLAPPED) error {
		mu.Lock()
		lens = append(lens, len(p))
		mu.Unlock()
		return filesystem.WriteFile(h, p, n, ov)
	})
	go func() { _, _ = io.Copy(io.Discard, host) }()
	total := 3*maxDeviceWrite + 100
	if n, err := dev.Write(make([]byte, total)); err != nil || n != total {
		t.Fatalf("write: %d, %v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	sum := 0
	for _, l := range lens {
		if l > maxDeviceWrite {
			t.Fatalf("a WriteFile of %d bytes", l)
		}
		sum += l
	}
	if sum != total || len(lens) != 4 {
		t.Fatalf("WriteFile sizes %v", lens)
	}
}

// The driver's "no room yet" answers are waited out, not passed up.
func TestOverlappedWriteRetriesWhileDeviceFull(t *testing.T) {
	for _, full := range []error{errDeviceCantWait, errDeviceNoRoom} {
		t.Run(full.Error(), func(t *testing.T) {
			dev, host := devicePair(t, nil)
			refusals := 3
			stubWriteFile(t, func(h foundation.HANDLE, p []byte, n *uint32, ov *systemio.OVERLAPPED) error {
				if refusals > 0 {
					refusals--
					return full
				}
				return filesystem.WriteFile(h, p, n, ov)
			})
			if n, err := dev.Write([]byte("reply")); err != nil || n != 5 {
				t.Fatalf("write: %d, %v", n, err)
			}
			got := make([]byte, 5)
			if _, err := io.ReadFull(host, got); err != nil || string(got) != "reply" {
				t.Fatalf("host read %q, %v", got, err)
			}
		})
	}
}

// A device that stays full past deviceWriteRetry fails the write, and any
// other error is not retried at all.
func TestOverlappedWriteGivesUp(t *testing.T) {
	dev, _ := devicePair(t, nil)
	retry := deviceWriteRetry
	t.Cleanup(func() { deviceWriteRetry = retry })
	deviceWriteRetry = 50 * time.Millisecond
	stubWriteFile(t, func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error {
		return errDeviceCantWait
	})
	if _, err := dev.Write([]byte("x")); !errors.Is(err, errDeviceCantWait) {
		t.Fatalf("write to a device that stays full: %v", err)
	}
	calls := 0
	other := syscall.Errno(foundation.ERROR_GEN_FAILURE)
	stubWriteFile(t, func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error {
		calls++
		return other
	})
	if _, err := dev.Write([]byte("x")); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("write failing otherwise: %v after %d calls", err, calls)
	}
}

// shortWriteTimeouts makes a write the host does not take give up quickly.
func shortWriteTimeouts(t *testing.T) {
	t.Helper()
	slow, timeout, cancelWait := deviceWriteSlow, deviceWriteTimeout, deviceCancelWait
	t.Cleanup(func() {
		deviceWriteSlow, deviceWriteTimeout, deviceCancelWait = slow, timeout, cancelWait
	})
	deviceWriteSlow, deviceWriteTimeout, deviceCancelWait = 100*time.Millisecond, 400*time.Millisecond, time.Second
}

// A host that stops reading leaves a write pending: it is reported as slow,
// then cancelled, and fails, rather than holding the writer for good. The
// device stays usable for a later write once the host drains.
func TestOverlappedWriteTimesOutWhenHostStopsReading(t *testing.T) {
	shortWriteTimeouts(t)
	logs := &logBuffer{}
	dev, host := devicePair(t, &winio.PipeConfig{InputBufferSize: 512, OutputBufferSize: 512})
	dev.useLog(slog.New(slog.NewTextHandler(logs, nil)))

	start := time.Now()
	_, err := dev.Write(make([]byte, 1<<20))
	if !errors.Is(err, errWriteTimedOut) {
		t.Fatalf("write to a host that never reads: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the timed-out write took %v", took)
	}
	for _, want := range []string{"device write is slow", "cancelling a device write"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	go func() { _, _ = io.Copy(io.Discard, host) }()
	if _, err := dev.Write([]byte("again")); err != nil {
		t.Fatalf("write after the host drains: %v", err)
	}
}

// A slow write that completes before the timeout is logged and succeeds.
func TestOverlappedSlowWriteCompletes(t *testing.T) {
	shortWriteTimeouts(t)
	deviceWriteTimeout = 5 * time.Second
	logs := &logBuffer{}
	dev, host := devicePair(t, &winio.PipeConfig{InputBufferSize: 512, OutputBufferSize: 512})
	dev.useLog(slog.New(slog.NewTextHandler(logs, nil)))
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.Copy(io.Discard, host)
	}()
	if _, err := dev.Write(make([]byte, 64<<10)); err != nil {
		t.Fatalf("slow write: %v", err)
	}
	if !strings.Contains(logs.String(), "slow device write completed") {
		t.Fatalf("log lacks the completion:\n%s", logs.String())
	}
}

// A cancelled write the driver never completes is abandoned: the write
// fails, later writes refuse at once, and Close still returns.
func TestOverlappedWedgedWriteIsAbandoned(t *testing.T) {
	shortWriteTimeouts(t)
	dev, _ := devicePair(t, &winio.PipeConfig{InputBufferSize: 512, OutputBufferSize: 512})
	dev.useLog(quietLog())
	real := getOverlappedResultEx
	t.Cleanup(func() { getOverlappedResultEx = real })
	getOverlappedResultEx = func(foundation.HANDLE, *systemio.OVERLAPPED, *uint32, uint32, bool) error {
		return errWaitTimeout
	}
	if _, err := dev.Write(make([]byte, 1<<20)); !errors.Is(err, errWriteWedged) {
		t.Fatalf("wedged write: %v", err)
	}
	getOverlappedResultEx = real
	if _, err := dev.Write([]byte("x")); !errors.Is(err, errWriteWedged) {
		t.Fatalf("write after abandoning one: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- dev.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung after an abandoned write")
	}
}

// End to end: the host stops reading, a large send times out, the channel
// resets, the device is opened again, and the host's hello on the new
// connection is answered.
func TestChannelRecoversFromHostThatStopsReading(t *testing.T) {
	shortWriteTimeouts(t)
	delay := reopenDelay
	t.Cleanup(func() { reopenDelay = delay })
	reopenDelay = 10 * time.Millisecond

	name, hostCh := listenHost(t, &winio.PipeConfig{InputBufferSize: 512, OutputBufferSize: 512})
	retryBusy(t, func() (*overlappedDevice, error) { return openOverlapped(name) }).Close() //nolint:errcheck
	acceptHost(t, hostCh)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	logs := &logBuffer{}
	mux := &Mux{Log: slog.New(slog.NewTextHandler(logs, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := mux.ConnectHypervisor(ctx, map[string]string{"device": name}, writeKeyFile(t, pub)); err != nil {
		t.Fatal(err)
	}
	acceptHost(t, hostCh) // the first host end, which never reads

	peer, ok := mux.hypervisorPeer().(*HypervisorPeer)
	if !ok {
		t.Fatalf("hypervisor peer is %T", mux.hypervisorPeer())
	}
	if err := peer.send("weave", "bulk", make([]byte, 1<<20)); err == nil {
		t.Fatal("a send the host never took succeeded")
	}

	host := acceptHost(t, hostCh) // opened again
	hostR, hostW := bufio.NewReader(host), bufio.NewWriter(host)
	in := mux.Receive(ctx, "weave")
	send(t, hostW, "weave", hvchannel.PreAuthKind, map[string]string{"id": "h2"})
	select {
	case <-in:
	case <-time.After(5 * time.Second):
		t.Fatal("hello on the reopened channel was not delivered")
	}
	if err := mux.hypervisorPeer().Send(ctx, "weave",
		hvchannel.PreAuthKind+".result", []byte(`{"id":"h2"}`)); err != nil {
		t.Fatal(err)
	}
	if got := readEnvelope(t, hostR); got.Kind != hvchannel.PreAuthKind+".result" {
		t.Fatalf("read %q", got.Kind)
	}
	if !strings.Contains(logs.String(), "the channel is being reset") {
		t.Fatalf("log lacks the reset:\n%s", logs.String())
	}
}

func stubWriteFile(
	t *testing.T,
	f func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error,
) {
	t.Helper()
	real := writeFile
	t.Cleanup(func() { writeFile = real })
	writeFile = f
}

func rawFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := hvchannel.WriteFrame(&b, payload); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
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
	// openDevice falls through to the stock candidates, and its error does
	// not carry the pipe's, so wait for the pipe to listen first.
	retryBusy(t, func() (*overlappedDevice, error) { return openOverlapped(name) }).Close() //nolint:errcheck
	acceptHost(t, hostCh)
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
