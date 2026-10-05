package transport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The macOS channel is /dev/cu.org.weave.agent.0: IOSerialFamily's tty over
// the virtio console port, and how it is read is what keeps it alive.
//
// Its input queue is about a kilobyte (TTYHOG). IOSerialBSDClient's receive
// thread moves bytes from the port into that queue and, when it is full,
// blocks itself until a read() or select() on the tty finds the queue below
// its low-water mark and wakes it. The check and the block are not atomic: a
// reader that empties the queue just before the thread marks itself blocked
// wakes nobody, and then sleeps in read() for bytes the sleeping thread holds.
// The rest of the frame in flight stays in the guest's port, and the channel
// is dead until core restarts. Under bulk host-to-guest traffic the queue is
// full most of the time, so this is not rare: a reader blocked in read()
// wedged within one or two 20 MB transfers, every time.
//
// So the queue is drained on its own goroutine, ttyDrainChunk at a time into
// ttyBuffer of userspace buffer (the frame decoder's pace never backs it up),
// and the drain waits in select() with a timeout, never in read(). Every
// select() repeats the low-water check, so it is the wakeup a lost one would
// have been, at most ttyPoll late — the same drain doing blocking reads
// wedged on the first 20 MB transfer; with select() it has not wedged.
//
// The termios is cfmakeraw's, plus: IXOFF, IXANY and IMAXBEL cleared, since
// any of them takes IOSerialBSDClient off its raw block-copy path onto
// per-byte line discipline (and IMAXBEL rings BEL into the output, a corrupt
// frame for the host, on overflow); and CLOCAL set, since the port has no
// carrier to lose and a modem-status change would otherwise hang the tty up
// and flush both queues.
const (
	ttyPoll        = 100 * time.Millisecond
	ttyBuffer      = 4 << 20
	ttyDrainChunk  = 64 << 10
	fdSetSizeLimit = 1024 // FD_SETSIZE: select cannot watch a higher fd
	// flushRead is FREAD (sys/fcntl.h), TIOCFLUSH's "input queue" selector;
	// x/sys/unix does not export it for darwin.
	flushRead = 0x0001
)

// Seams over the tty calls, so the drain's error paths run under test.
var (
	ttySelect = unix.Select
	ttyRead   = unix.Read
)

// errTTYEOF is a zero-byte read from a tty select() reported readable: with
// CLOCAL set, only a revoked or detached port does that.
var errTTYEOF = errors.New("transport: channel tty returned end of file")

// errFDBeyondSelect is a channel fd at or past FD_SETSIZE.
var errFDBeyondSelect = errors.New("transport: channel tty fd is beyond select's reach")

func openTTY(f *os.File) (io.ReadWriteCloser, error) {
	fd := int(f.Fd())
	if fd >= fdSetSizeLimit {
		return nil, fmt.Errorf("%w: fd %d", errFDBeyondSelect, fd)
	}
	if err := makeChannelRaw(fd); err != nil {
		return nil, err
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("channel tty: %w", err)
	}
	t := &drainedTTY{
		f: f, rc: rc, q: newByteQueue(ttyBuffer), done: make(chan struct{}),
		sel: ttySelect, read: ttyRead,
	}
	go t.drain()
	return t, nil
}

// makeChannelRaw is cfmakeraw plus what the channel needs on top (see the
// const block), then discards input that arrived before this open: the rest
// of a frame a previous reader was part-way through would be read as the
// start of a new one.
func makeChannelRaw(fd int) error {
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return fmt.Errorf("reading the channel's termios: %w", err)
	}
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR |
		unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY | unix.IMAXBEL
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, t); err != nil {
		return fmt.Errorf("setting the channel's termios: %w", err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, flushRead); err != nil {
		return fmt.Errorf("flushing the channel's stale input: %w", err)
	}
	return nil
}

// drainedTTY reads from the userspace buffer the drain fills, and writes to
// the tty directly.
type drainedTTY struct {
	f    *os.File
	rc   syscall.RawConn
	q    *byteQueue
	once sync.Once
	done chan struct{}
	sel  func(int, *unix.FdSet, *unix.FdSet, *unix.FdSet, *unix.Timeval) (int, error)
	read func(int, []byte) (int, error)
}

func (t *drainedTTY) Read(p []byte) (int, error) { return t.q.Read(p) }

func (t *drainedTTY) Write(p []byte) (int, error) {
	return t.f.Write(p) //nolint:wrapcheck // the tty's own error, as for any other channel
}

// Close ends the drain and closes the tty. The drain notices within ttyPoll;
// the file's close waits for it to leave the fd, so the fd number is never
// reused under a select().
func (t *drainedTTY) Close() error {
	var err error
	t.once.Do(func() {
		close(t.done)
		t.q.Close()
		err = t.f.Close()
	})
	return err //nolint:wrapcheck // the tty's own error
}

func (t *drainedTTY) drain() {
	buf := make([]byte, ttyDrainChunk)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		n, err := t.readSome(buf)
		if n > 0 {
			if _, werr := t.q.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			t.q.finish(err)
			return
		}
	}
}

// readSome waits up to ttyPoll for input and reads what there is. Holding the
// RawConn for the whole call keeps the fd open under the select().
func (t *drainedTTY) readSome(buf []byte) (int, error) {
	var n int
	var err error
	cerr := t.rc.Read(func(fd uintptr) bool {
		var set unix.FdSet
		set.Set(int(fd))
		tv := unix.NsecToTimeval(int64(ttyPoll))
		k, serr := t.sel(int(fd)+1, &set, nil, nil, &tv)
		switch {
		case errors.Is(serr, unix.EINTR):
			return true
		case serr != nil:
			err = fmt.Errorf("waiting on the channel tty: %w", serr)
			return true
		case k == 0:
			return true
		}
		n, err = t.read(int(fd), buf)
		switch {
		case errors.Is(err, unix.EINTR), errors.Is(err, unix.EAGAIN):
			n, err = 0, nil
		case err != nil:
			n, err = 0, fmt.Errorf("reading the channel tty: %w", err)
		case n == 0:
			err = errTTYEOF
		}
		return true
	})
	if cerr != nil {
		return 0, fmt.Errorf("channel tty: %w", cerr)
	}
	return n, err
}
