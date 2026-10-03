package ipc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

const network = NetworkPipe

// pipeSDDL restricts the pipe to SYSTEM and the Administrators group:
//
//	D:  discretionary ACL
//	(A;;GA;;;SY)  allow generic-all to SYSTEM
//	(A;;GA;;;BA)  allow generic-all to Builtin Administrators
//
// This replaces go-winio's default (which grants broad access), closing
// the "any local user can open the control/host pipe" hole. Modules that
// run at lower privilege need a wider SDDL; that is set per-listener via
// ListenPipeSDDL when per-module Windows privilege lands.
const pipeSDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)"

// go-winio creates a pipe without blocking and takes no context.
func listen(_ context.Context, addr string) (net.Listener, error) {
	return ListenPipeSDDL(addr, pipeSDDL)
}

// ListenPipeSDDL creates a named-pipe listener with an explicit SDDL, for
// callers (privilege-dropped modules) that need a wider descriptor than
// the SYSTEM+Administrators default.
func ListenPipeSDDL(addr, sddl string) (net.Listener, error) {
	l, err := winio.ListenPipe(addr, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	return &pipeListener{Listener: l, closed: make(chan struct{})}, nil
}

// pipeCloseTimeout bounds how long Close waits for go-winio to let go.
const pipeCloseTimeout = 2 * time.Second

// pipeListener works around a go-winio (v0.6.2) race that can make Close
// block forever. Close hands its signal to whatever is reading the listener's
// close channel; when that is an Accept still waiting for a client, the
// aborted connect can come back as an error other than ErrFileClosed, so the
// listener goroutine treats it as an ordinary failed Accept, never exits, and
// Close waits on it for good. gRPC calls Close from Stop and GracefulStop
// while holding its server mutex, and the Serve goroutine then needs that
// mutex to handle the failed Accept: the module never exits. Seen on
// windows-latest as a ten-minute test timeout.
//
// Close here is therefore bounded and idempotent, and Accept refuses once
// Close has begun. On timeout the go-winio goroutine and the pipe's first
// handle leak, which is preferable to a module that cannot shut down.
type pipeListener struct {
	net.Listener
	once   sync.Once
	closed chan struct{}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	c, err := l.Listener.Accept()
	if err != nil {
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		default:
		}
	}
	// Unwrapped: net.Listener's contract. gRPC's Serve type-asserts the
	// error for Temporary() to decide whether to retry.
	return c, err //nolint:wrapcheck // net.Listener contract: callers type-assert the error
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		done := make(chan struct{})
		go func() {
			l.Listener.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(pipeCloseTimeout):
		}
	})
	return nil
}

func dial(ctx context.Context, netw, addr string) (net.Conn, error) {
	if netw != NetworkPipe {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedNetwork, netw)
	}
	c, err := winio.DialPipeContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial: %w", err)
	}
	return c, nil
}
