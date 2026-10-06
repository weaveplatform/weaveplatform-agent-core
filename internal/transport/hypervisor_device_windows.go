package transport

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	systemio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
)

// The Windows channel device is opened for overlapped I/O, and that is a
// correctness requirement, not a performance one.
//
// Windows serialises every operation on a handle opened without
// FILE_FLAG_OVERLAPPED: a WriteFile waits for whatever ReadFile is in flight on
// the same handle. The read loop always has a read in flight, so on a
// synchronous handle each reply sat in the kernel until the host happened to
// send something else, which completed the read and let the write through.
// Host-side traces of a Windows 11 guest showed exactly that — the guest's
// bytes arriving in the same millisecond as the host's next write — so every
// presence hello missed its window and the channel never authenticated.
// os.OpenFile cannot be told otherwise: it always opens synchronously.
//
// Each direction owns one OVERLAPPED and one event, so a read that is pending
// forever never holds up a write. Reads and writes are each serialised within
// their own direction, which the peer already guarantees (one read loop, one
// write mutex).
//
// The virtio-serial driver (vioserial, VIOSerialPortWrite) does not queue a
// write it has no room for: when the port's out virtqueue is still full of
// what the host has not consumed it fails the write at once with
// STATUS_CANT_WAIT, and when the queue has too few free descriptors for the
// buffer, with STATUS_INSUFFICIENT_RESOURCES. Neither means the channel is
// broken, only that the host has not caught up, so Write retries both, and it
// writes in pieces small enough to need few descriptors. Passing either up
// instead failed the peer's buffered writer for good: the channel went on
// reading the host's requests and never answered another.
//
// A write the host never takes is bounded too. The driver completes a write
// only once the host has consumed it, so a host that stops draining the port
// leaves the write pending, and with it the peer's write mutex, which the read
// loop needs for every reply: the whole channel wedges. A write still pending
// after deviceWriteSlow is logged; after deviceWriteTimeout it is cancelled and
// fails, and the peer resets the channel.

// The Win32 errors the device reads specially.
var (
	errIOPending        = syscall.Errno(foundation.ERROR_IO_PENDING)
	errDeviceAborted    = syscall.Errno(foundation.ERROR_OPERATION_ABORTED)
	errDeviceBrokenPipe = syscall.Errno(foundation.ERROR_BROKEN_PIPE)
	errDeviceHandleEOF  = syscall.Errno(foundation.ERROR_HANDLE_EOF)
	errDeviceCantWait   = syscall.Errno(foundation.ERROR_CANT_WAIT)
	errDeviceNoRoom     = syscall.Errno(foundation.ERROR_NO_SYSTEM_RESOURCES)
)

// maxDeviceWrite bounds one WriteFile: at most two pages, so two descriptors.
const maxDeviceWrite = 4096

// How Write waits out a full device: backing off from the first to the
// longest pause, for at most deviceWriteRetry in all. A host that has taken
// nothing for that long is not coming back for this write; the error ends
// the channel, which is then opened again.
var (
	deviceWriteRetry      = 10 * time.Second
	deviceWriteFirstPause = time.Millisecond
	deviceWriteMaxPause   = 50 * time.Millisecond
)

// How long one write may stay pending: logged after deviceWriteSlow,
// cancelled after deviceWriteTimeout. deviceCancelWait bounds the wait for a
// cancelled write to complete; a driver that holds it longer has the write
// abandoned (see abandon).
var (
	deviceWriteSlow    = 2 * time.Second
	deviceWriteTimeout = 15 * time.Second
	deviceCancelWait   = 5 * time.Second
)

var (
	// errWriteTimedOut: the host took nothing of a write for deviceWriteTimeout.
	errWriteTimedOut = errors.New("the host did not take the write in time; cancelled")
	// errWriteWedged: a cancelled write the driver would not give back.
	errWriteWedged = errors.New(
		"a cancelled write never completed; the device's write side is abandoned",
	)
	// The waits' "not yet".
	errWaitTimeout  = syscall.Errno(foundation.WAIT_TIMEOUT)
	errIOIncomplete = syscall.Errno(foundation.ERROR_IO_INCOMPLETE)
)

// abandoned keeps every OVERLAPPED a wedged write still owns reachable for the
// life of the process: the kernel writes to it whenever the write does
// complete, and its event must never be closed and its number reused.
var (
	abandonedMu sync.Mutex
	abandoned   []*systemio.OVERLAPPED
)

// Seams for the tests: the failures the real calls cannot be made to give.
var (
	createIOEvent = func() (foundation.HANDLE, error) {
		return threading.CreateEvent(nil, true, false, nil)
	}
	writeFile = filesystem.WriteFile
)

// overlappedDevice is an io.ReadWriteCloser over a handle opened with
// FILE_FLAG_OVERLAPPED.
type overlappedDevice struct {
	h      foundation.HANDLE
	rd, wr deviceOp
	log    *slog.Logger

	// mu orders issuing I/O against Close. An operation is only issued while
	// the device is open, and Close cancels under the same lock, so no
	// operation can slip in after the cancel and wait forever. inflight lets
	// Close keep the handle open until every cancelled operation has
	// completed: closing it earlier would let Windows hand the number to
	// someone else while GetOverlappedResult still waits on it.
	mu       sync.Mutex
	closed   bool
	inflight sync.WaitGroup
}

// deviceOp is one direction's OVERLAPPED. It is heap-allocated and owned by
// the device because the kernel writes to it after the call that issued the
// operation has returned.
type deviceOp struct {
	mu sync.Mutex
	ov *systemio.OVERLAPPED
	// wedged: ov was abandoned to a write that never completed; nothing may
	// use it again. Guarded by mu.
	wedged bool
}

// openOverlapped opens path for overlapped reading and writing.
func openOverlapped(path string) (*overlappedDevice, error) {
	h, err := filesystem.CreateFile(path,
		uint32(foundation.GENERIC_READ|foundation.GENERIC_WRITE),
		filesystem.FILE_SHARE_READ|filesystem.FILE_SHARE_WRITE,
		nil, filesystem.OPEN_EXISTING, filesystem.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	rev, err := createIOEvent()
	if err != nil {
		foundation.CloseHandle(h) //nolint:errcheck // nothing to do about a failed close
		return nil, fmt.Errorf("read event for %s: %w", path, err)
	}
	wev, err := createIOEvent()
	if err != nil {
		foundation.CloseHandle(rev) //nolint:errcheck // as above
		foundation.CloseHandle(h)   //nolint:errcheck // as above
		return nil, fmt.Errorf("write event for %s: %w", path, err)
	}
	return &overlappedDevice{
		h:   h,
		rd:  deviceOp{ov: &systemio.OVERLAPPED{HEvent: rev}},
		wr:  deviceOp{ov: &systemio.OVERLAPPED{HEvent: wev}},
		log: slog.Default(),
	}, nil
}

// useLog sets where the device reports slow and cancelled writes. The peer
// that owns the device calls it before any I/O.
func (d *overlappedDevice) useLog(l *slog.Logger) { d.log = l }

// Read returns what one ReadFile delivered, which may be less than len(p). A
// read of nothing, or the far end going away, is io.EOF, as it is on os.File.
func (d *overlappedDevice) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	d.rd.mu.Lock()
	defer d.rd.mu.Unlock()
	n, err := d.do(d.rd.ov, p, filesystem.ReadFile, d.waitRead)
	switch {
	case errors.Is(err, errDeviceBrokenPipe), errors.Is(err, errDeviceHandleEOF):
		return n, io.EOF
	case err != nil:
		return n, err
	case n == 0:
		return 0, io.EOF
	}
	return n, nil
}

// Write writes all of p, in pieces of at most maxDeviceWrite, retrying while
// the device has no room for the next one.
func (d *overlappedDevice) Write(p []byte) (int, error) {
	d.wr.mu.Lock()
	defer d.wr.mu.Unlock()
	if d.wr.wedged {
		return 0, fmt.Errorf("transport: channel device: %w", errWriteWedged)
	}
	written := 0
	for written < len(p) {
		n, err := d.writeChunk(p[written:min(len(p), written+maxDeviceWrite)])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// writeChunk issues one write, again and again while the device reports it
// full, with a growing pause, until it is taken, fails otherwise, or
// deviceWriteRetry has passed.
func (d *overlappedDevice) writeChunk(p []byte) (int, error) {
	deadline := time.Now().Add(deviceWriteRetry)
	pause := deviceWriteFirstPause
	for {
		n, err := d.do(d.wr.ov, p, writeFile, d.waitWrite)
		if err == nil || !deviceFull(err) {
			return n, err
		}
		if time.Now().After(deadline) {
			return n, fmt.Errorf("%w (the host took nothing for %v)", err, deviceWriteRetry)
		}
		time.Sleep(pause)
		pause = min(2*pause, deviceWriteMaxPause)
	}
}

// deviceFull reports the driver's "no room yet" answers to a write.
func deviceFull(err error) bool {
	return errors.Is(err, errDeviceCantWait) || errors.Is(err, errDeviceNoRoom)
}

// do issues one operation and waits for it to complete.
func (d *overlappedDevice) do(
	ov *systemio.OVERLAPPED,
	p []byte,
	op func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error,
	wait func(*systemio.OVERLAPPED, int) (uint32, error),
) (int, error) {
	if err := d.issue(ov, p, op); err != nil {
		return 0, err
	}
	defer d.inflight.Done()
	// Waited on even when the call completed at once: the event is signalled
	// either way, and the wait is the one place the count is read.
	n, err := wait(ov, len(p))
	// The kernel has been using p until now.
	runtime.KeepAlive(p)
	if err != nil {
		return int(n), d.ioErr(err)
	}
	return int(n), nil
}

// waitRead waits as long as the read takes: the read loop's read is pending
// whenever the host has nothing to say, and Close is what ends it.
func (d *overlappedDevice) waitRead(ov *systemio.OVERLAPPED, _ int) (uint32, error) {
	var n uint32
	err := systemio.GetOverlappedResult(d.h, ov, &n, true)
	return n, err //nolint:wrapcheck // do names it
}

// waitWrite waits for a write for at most deviceWriteTimeout, logging one
// still pending after deviceWriteSlow, and then cancels it.
func (d *overlappedDevice) waitWrite(ov *systemio.OVERLAPPED, size int) (uint32, error) {
	start := time.Now()
	n, err := d.waitFor(ov, deviceWriteSlow)
	if !pending(err) {
		return n, err
	}
	d.log.Warn("hypervisor channel: a device write is slow; the host has not taken it",
		"bytes", size, "waited", time.Since(start).Round(time.Millisecond).String())
	n, err = d.waitFor(ov, deviceWriteTimeout-time.Since(start))
	if !pending(err) {
		d.log.Warn("hypervisor channel: the slow device write completed",
			"bytes", size, "took", time.Since(start).Round(time.Millisecond).String())
		return n, err
	}
	d.log.Warn("hypervisor channel: cancelling a device write the host has not taken",
		"bytes", size, "waited", time.Since(start).Round(time.Millisecond).String())
	_ = systemio.CancelIoEx(d.h, ov) // ERROR_NOT_FOUND: it completed meanwhile
	n, err = d.waitFor(ov, deviceCancelWait)
	switch {
	case err == nil:
		return n, nil // it completed before the cancel took
	case pending(err):
		d.abandon(ov)
		return n, errWriteWedged
	case errors.Is(err, errDeviceAborted):
		return n, fmt.Errorf("%w after %v", errWriteTimedOut, deviceWriteTimeout)
	}
	return n, err
}

// waitFor waits up to limit for the operation on ov.
func (d *overlappedDevice) waitFor(ov *systemio.OVERLAPPED, limit time.Duration) (uint32, error) {
	var n uint32
	ms := uint32(max(limit, 0).Milliseconds()) //nolint:gosec // bounded by the timeouts above
	err := getOverlappedResultEx(d.h, ov, &n, ms, false)
	return n, err //nolint:wrapcheck // do names it
}

var getOverlappedResultEx = systemio.GetOverlappedResultEx

// pending reports a wait that ran out before the operation completed.
func pending(err error) bool {
	return errors.Is(err, errWaitTimeout) || errors.Is(err, errIOIncomplete)
}

// abandon gives up on a write the driver will not complete: its OVERLAPPED
// and event stay alive and unused for good, and this device writes no more.
func (d *overlappedDevice) abandon(ov *systemio.OVERLAPPED) {
	d.log.Error("hypervisor channel: a cancelled device write never completed; abandoning it")
	abandonedMu.Lock()
	abandoned = append(abandoned, ov)
	abandonedMu.Unlock()
	d.wr.wedged = true
}

func (d *overlappedDevice) issue(
	ov *systemio.OVERLAPPED,
	p []byte,
	op func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("transport: channel device: %w", os.ErrClosed)
	}
	if err := op(d.h, p, nil, ov); err != nil && !errors.Is(err, errIOPending) {
		return d.ioErr(err)
	}
	d.inflight.Add(1)
	return nil
}

// ioErr names a failed operation. One aborted because Close cancelled it is
// os.ErrClosed, as a closed os.File or net.Conn reports it; anything else —
// the device going away included — is returned for the read loop to end on,
// and the device is opened again from there.
func (d *overlappedDevice) ioErr(err error) error {
	if errors.Is(err, errDeviceAborted) {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return fmt.Errorf("transport: channel device: %w", os.ErrClosed)
		}
	}
	return fmt.Errorf("transport: channel device: %w", err)
}

// Close cancels any read or write in flight, waits for them to finish, and
// closes the handle. It is safe to call more than once and from any goroutine;
// the read loop, the stall watch and the peer's owner all may.
func (d *overlappedDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return fmt.Errorf("transport: channel device: %w", os.ErrClosed)
	}
	d.closed = true
	// A nil OVERLAPPED cancels everything on the handle, from every thread.
	// ERROR_NOT_FOUND (nothing pending) is the common, harmless failure.
	_ = systemio.CancelIoEx(d.h, nil)
	d.mu.Unlock()
	d.inflight.Wait()
	foundation.CloseHandle(d.rd.ov.HEvent) //nolint:errcheck // nothing to do about a failed close
	if !d.wr.wedged {
		foundation.CloseHandle(d.wr.ov.HEvent) //nolint:errcheck // as above
	}
	if err := foundation.CloseHandle(d.h); err != nil {
		return fmt.Errorf("transport: closing the channel device: %w", err)
	}
	return nil
}
