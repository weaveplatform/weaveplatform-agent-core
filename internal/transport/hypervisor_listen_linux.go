package transport

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenSocket listens on AF_VSOCK, any local CID, at the probed port.
func listenSocket(attrs map[string]string, _ *slog.Logger) (connListener, error) {
	if attrs["kind"] != "vsock" {
		return nil, fmt.Errorf("%w: kind %q on linux", errChannelAttrs, attrs["kind"])
	}
	port, err := channelPort(attrs)
	if err != nil {
		return nil, err
	}
	return listenVsock(unix.VMADDR_CID_ANY, port)
}

func listenVsock(cid, port uint32) (connListener, error) {
	l, err := listenStream(unix.AF_VSOCK, &unix.SockaddrVM{CID: cid, Port: port})
	if err != nil {
		return nil, fmt.Errorf("vsock port %d: %w", port, err)
	}
	return l, nil
}

// listenStream is the family-independent part, so tests can drive it over
// AF_UNIX on kernels (and containers) without AF_VSOCK.
func listenStream(domain int, sa unix.Sockaddr) (*streamListener, error) {
	// Non-blocking from the start so that os.NewFile hands the fd to the
	// runtime poller. A blocking accept(2) is not reliably woken by close(2)
	// on Linux, which would leave Close unable to stop the accept loop.
	fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}
	f := os.NewFile(uintptr(fd), "hypervisor-channel")
	// SyscallConn cannot fail on a file that was just opened; the check is
	// for the contract, not a path anyone has seen.
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("listener: %w", err)
	}
	return &streamListener{f: f, rc: rc}, nil
}

type streamListener struct {
	f  *os.File
	rc syscall.RawConn
}

func (l *streamListener) Accept() (io.ReadWriteCloser, error) {
	var nfd int
	var aerr error
	err := l.rc.Read(func(fd uintptr) bool {
		nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		return !errors.Is(aerr, unix.EAGAIN)
	})
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	if aerr != nil {
		return nil, fmt.Errorf("accept: %w", aerr)
	}
	// Pollable for the same reason as the listener: closing a replaced
	// connection has to unblock its read loop.
	return os.NewFile(uintptr(nfd), "hypervisor-channel-conn"), nil
}

func (l *streamListener) Close() error { return l.f.Close() } //nolint:wrapcheck // nothing to add
