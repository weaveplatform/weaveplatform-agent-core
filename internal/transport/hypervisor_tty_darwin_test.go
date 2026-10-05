package transport

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY returns a pty master and its slave's path. The slave stands in for
// /dev/cu.org.weave.agent.0: a tty whose input the master writes.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	fd := int(m.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		t.Fatal(err)
	}
	var name [128]byte
	// x/sys/unix has no wrapper for TIOCPTYGNAME, which fills a buffer.
	//nolint:staticcheck // SA1019: no non-deprecated way to pass a buffer to this ioctl
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCPTYGNAME),
		uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		t.Fatal(e)
	}
	return m, string(name[:bytes.IndexByte(name[:], 0)])
}

func openChannelPTY(t *testing.T) (*os.File, *drainedTTY) {
	t.Helper()
	m, slave := openPTY(t)
	rwc, err := openDevice(map[string]string{"device": slave})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rwc.Close() })
	d, ok := rwc.(*drainedTTY)
	if !ok {
		t.Fatalf("a tty channel opened as %T", rwc)
	}
	return m, d
}

func TestChannelTTYIsRaw(t *testing.T) {
	_, d := openChannelPTY(t)
	tio, err := unix.IoctlGetTermios(int(d.f.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Iflag&(unix.IMAXBEL|unix.IXON|unix.IXOFF|unix.IXANY|unix.ICRNL) != 0 {
		t.Errorf("iflag %#x", tio.Iflag)
	}
	if tio.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG|unix.IEXTEN) != 0 {
		t.Errorf("lflag %#x", tio.Lflag)
	}
	if tio.Oflag&unix.OPOST != 0 ||
		tio.Cflag&(unix.CLOCAL|unix.CREAD|unix.CS8) != unix.CLOCAL|unix.CREAD|unix.CS8 {
		t.Errorf("oflag %#x cflag %#x", tio.Oflag, tio.Cflag)
	}
}

// What a previous reader left in the tty is not read as the start of a frame.
func TestChannelTTYDiscardsStaleInput(t *testing.T) {
	m, slave := openPTY(t)
	s, err := os.OpenFile(slave, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := makeChannelRaw(int(s.Fd())); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write([]byte("stale")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	rwc, err := openDevice(map[string]string{"device": slave})
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	if _, err := m.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := rwc.Read(buf)
	if err != nil || string(buf[:n]) != "fresh" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
}

// A host writing flat out while the decoder reads slowly: the drain keeps the
// tty emptied into userspace (the buffer grows far past the tty's own
// kilobyte), and every byte arrives in order.
func TestChannelTTYDrainKeepsUp(t *testing.T) {
	m, d := openChannelPTY(t)
	want := make([]byte, 4<<20)
	for i := range want {
		want[i] = byte(rand.IntN(256))
	}
	go func() {
		for p := want; len(p) > 0; {
			n, err := m.Write(p[:min(len(p), 8192)])
			if err != nil {
				return
			}
			p = p[n:]
		}
	}()
	time.Sleep(300 * time.Millisecond) // the decoder is busy; the drain is not
	d.q.mu.Lock()
	buffered := len(d.q.buf) - d.q.off
	d.q.mu.Unlock()
	if buffered < 64<<10 {
		t.Fatalf("only %d bytes drained while the reader was busy", buffered)
	}
	got := make([]byte, 0, len(want))
	buf := make([]byte, 1000)
	for len(got) < len(want) {
		n, err := d.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the stream through the drain differs")
	}
	if _, err := d.Write([]byte("out")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 3)
	if _, err := io.ReadFull(m, out); err != nil || string(out) != "out" {
		t.Fatalf("write side: %q %v", out, err)
	}
}

func TestChannelTTYCloseEndsReads(t *testing.T) {
	_, d := openChannelPTY(t)
	done := make(chan error, 1)
	go func() {
		_, err := d.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal("a second close must be harmless")
	}
	select {
	case err := <-done:
		if !errors.Is(err, errQueueClosed) {
			t.Fatalf("read after close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close left a reader blocked")
	}
}

// The drain's failures end the stream for the decoder with the reason;
// interruptions and a spurious wakeup do not.
func TestChannelTTYDrainErrors(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name   string
		sel    func(int, *unix.FdSet, *unix.FdSet, *unix.FdSet, *unix.Timeval) (int, error)
		read   func(int, []byte) (int, error)
		target error
	}{
		{
			"select",
			func(int, *unix.FdSet, *unix.FdSet, *unix.FdSet, *unix.Timeval) (int, error) { return 0, errBoom },
			nil,
			errBoom,
		},
		{"read", nil, func(int, []byte) (int, error) { return 0, errBoom }, errBoom},
		{"eof", nil, func(int, []byte) (int, error) { return 0, nil }, errTTYEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origSel, origRead := ttySelect, ttyRead
			t.Cleanup(func() { ttySelect, ttyRead = origSel, origRead })
			calls := 0
			ttySelect = func(n int, r, w, e *unix.FdSet, tv *unix.Timeval) (int, error) {
				calls++
				if calls == 1 {
					return 0, unix.EINTR
				}
				if c.sel != nil {
					return c.sel(n, r, w, e, tv)
				}
				return 1, nil
			}
			reads := 0
			ttyRead = func(fd int, p []byte) (int, error) {
				reads++
				switch reads {
				case 1:
					return 0, unix.EAGAIN
				case 2:
					return copy(p, "ab"), nil
				}
				return c.read(fd, p)
			}
			m, slave := openPTY(t)
			_ = m
			rwc, err := openDevice(map[string]string{"device": slave})
			if err != nil {
				t.Fatal(err)
			}
			defer rwc.Close()
			all, err := io.ReadAll(rwc)
			if !errors.Is(err, c.target) {
				t.Fatalf("err %v, want %v", err, c.target)
			}
			if c.sel == nil && string(all) != "ab" {
				t.Fatalf("read %q before the failure", all)
			}
		})
	}
}

func TestMakeChannelRawRefusesANonTTY(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := makeChannelRaw(int(f.Fd())); err == nil || !strings.Contains(err.Error(), "termios") {
		t.Fatalf("err %v", err)
	}
	if _, err := openTTY(f); err == nil {
		t.Fatal("openTTY accepted a regular file")
	}
}
