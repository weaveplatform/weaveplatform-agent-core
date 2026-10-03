package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// unixKind is the channel kind for a container: core listens on a Unix socket
// in a directory the container host bind-mounts, and the host dials it.
const unixKind = "unix"

// unixListener adapts a net.Listener on a Unix socket to connListener.
type unixListener struct {
	l    net.Listener
	path string
}

func (u *unixListener) Accept() (io.ReadWriteCloser, error) {
	c, err := u.l.Accept()
	if err != nil {
		return nil, fmt.Errorf("accepting on %s: %w", u.path, err)
	}
	return c, nil
}

// Close stops accepting; net removes the socket file it created.
func (u *unixListener) Close() error { return u.l.Close() } //nolint:wrapcheck // net names the socket

// listenUnix listens on a Unix socket at path.
//
// A socket left by a previous core is replaced: core restarts in place, and a
// stale socket would otherwise make every restart fail to bind. Anything else
// at the path is refused rather than deleted, because a path that is not a
// socket was put there by someone who meant it.
func listenUnix(path string) (connListener, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: unix channel without a path", errChannelAttrs)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: %s exists and is not a socket", errChannelAttrs, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing a stale channel socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking the channel socket: %w", err)
	}
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("unix channel %s: %w", path, err)
	}
	// Owner only. The host that dials runs as root (or as core's user), and
	// the channel key, not the mode, is what admits it.
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("restricting the channel socket: %w", err)
	}
	return &unixListener{l: l, path: path}, nil
}
