//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
)

const network = NetworkUnix

func listen(ctx context.Context, addr string) (net.Listener, error) {
	// A stale socket file from a crashed predecessor blocks bind; remove
	// it. Liveness is the supervisor's problem, not the filesystem's.
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: clearing stale socket: %w", err)
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	// Belt and braces: the parent directory's 0700 is the real gate.
	if err := os.Chmod(addr, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("ipc: restricting socket mode: %w", err)
	}
	return l, nil
}

func dial(ctx context.Context, netw, addr string) (net.Conn, error) {
	if netw != NetworkUnix {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedNetwork, netw)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial: %w", err)
	}
	return c, nil
}
