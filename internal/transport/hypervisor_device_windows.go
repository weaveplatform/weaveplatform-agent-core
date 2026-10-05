package transport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"

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

// The Win32 errors the device reads specially.
var (
	errIOPending        = syscall.Errno(foundation.ERROR_IO_PENDING)
	errDeviceAborted    = syscall.Errno(foundation.ERROR_OPERATION_ABORTED)
	errDeviceBrokenPipe = syscall.Errno(foundation.ERROR_BROKEN_PIPE)
	errDeviceHandleEOF  = syscall.Errno(foundation.ERROR_HANDLE_EOF)
)

// Seams for the tests: the failures the real calls cannot be made to give.
var (
	createIOEvent = func() (foundation.HANDLE, error) {
		return threading.CreateEvent(nil, true, false, nil)
	}
)

// overlappedDevice is an io.ReadWriteCloser over a handle opened with
// FILE_FLAG_OVERLAPPED.
type overlappedDevice struct {
	h      foundation.HANDLE
	rd, wr deviceOp

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
		h:  h,
		rd: deviceOp{ov: &systemio.OVERLAPPED{HEvent: rev}},
		wr: deviceOp{ov: &systemio.OVERLAPPED{HEvent: wev}},
	}, nil
}

// Read returns what one ReadFile delivered, which may be less than len(p). A
// read of nothing, or the far end going away, is io.EOF, as it is on os.File.
func (d *overlappedDevice) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	d.rd.mu.Lock()
	defer d.rd.mu.Unlock()
	n, err := d.do(d.rd.ov, p, filesystem.ReadFile)
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

// Write writes all of p, issuing as many WriteFiles as it takes.
func (d *overlappedDevice) Write(p []byte) (int, error) {
	d.wr.mu.Lock()
	defer d.wr.mu.Unlock()
	written := 0
	for written < len(p) {
		n, err := d.do(d.wr.ov, p[written:], filesystem.WriteFile)
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

// do issues one operation and waits for it to complete.
func (d *overlappedDevice) do(
	ov *systemio.OVERLAPPED,
	p []byte,
	op func(foundation.HANDLE, []byte, *uint32, *systemio.OVERLAPPED) error,
) (int, error) {
	if err := d.issue(ov, p, op); err != nil {
		return 0, err
	}
	defer d.inflight.Done()
	// Waited on even when the call completed at once: the event is signalled
	// either way, and GetOverlappedResult is the one place the count is read.
	var n uint32
	err := systemio.GetOverlappedResult(d.h, ov, &n, true)
	// The kernel has been writing into p until now.
	runtime.KeepAlive(p)
	if err != nil {
		return int(n), d.ioErr(err)
	}
	return int(n), nil
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
	foundation.CloseHandle(d.wr.ov.HEvent) //nolint:errcheck // as above
	if err := foundation.CloseHandle(d.h); err != nil {
		return fmt.Errorf("transport: closing the channel device: %w", err)
	}
	return nil
}
