package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"
)

// connListener is the guest end of a socket channel: AF_VSOCK on Linux,
// AF_HYPERV on Windows. Neither fits net.Listener (the net package knows
// neither family), and the accept loop needs nothing more than this.
type connListener interface {
	Accept() (io.ReadWriteCloser, error)
	// Close must unblock a pending Accept.
	Close() error
}

// Seams for the accept loop's tests. Nothing but a test writes them.
var (
	listenChannel = listenAny
	// acceptRetry paces the loop after a failed accept, so a listener that
	// fails persistently costs a log line a second rather than a core.
	acceptRetry = time.Second
)

var errChannelAttrs = errors.New("transport: unusable hypervisor channel attributes")

// listenAny picks the listener for a socket channel: a unix socket the same way
// on every OS, otherwise the platform's hypervisor socket family.
func listenAny(attrs map[string]string, log *slog.Logger) (connListener, error) {
	if attrs["kind"] == unixKind {
		return listenUnix(attrs["path"])
	}
	return listenSocket(attrs, log)
}

// channelPort reads the probed port back out of the capability attributes.
func channelPort(attrs map[string]string) (uint32, error) {
	port, err := strconv.ParseUint(attrs["port"], 10, 32)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%w: port %q", errChannelAttrs, attrs["port"])
	}
	return uint32(port), nil
}

// vsockServiceID is the HvSocket service GUID for a vsock port: Microsoft's
// vsock template with the port in the first field. Hyper-V maps AF_VSOCK port
// P on a Linux guest to this service, and a Windows guest listens on it
// directly, so the host dials the same identity for either guest OS.
func vsockServiceID(port uint32) string {
	return fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", port)
}

func (m *Mux) listenHypervisor(ctx context.Context, attrs map[string]string, keyPath string) error {
	l, err := listenChannel(attrs, m.Log)
	if err != nil {
		return fmt.Errorf("transport: listening for the hypervisor channel: %w", err)
	}
	go m.serveHypervisor(ctx, l, newChannelAuth(m.Log, keyPath))
	return nil
}

// serveHypervisor accepts host connections until ctx ends, making each one THE
// hypervisor peer.
//
// A newer connection replaces the older one, closing it. The host reconnects
// after it restarts, and the frame protocol cannot have two readers (see
// hypervisor.go), so the only safe owner is the newest: a host that dialled
// again has, by definition, given up on its previous connection, and keeping
// the old one would leave a half-dead peer holding the channel. A replaced
// host that is in fact still alive just sees its connection close.
//
// Each connection starts unauthenticated. Proof given on the previous
// connection says nothing about whoever is on this one.
//
// Between connections the peer is nil, so queue_offline sends queue rather
// than fail; once a connection authenticates the queue is flushed to it.
func (m *Mux) serveHypervisor(ctx context.Context, l connListener, auth *channelAuth) {
	stop := context.AfterFunc(
		ctx,
		func() { l.Close() },
	)
	defer stop()
	var current *HypervisorPeer
	for {
		rwc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				if current != nil {
					current.Close()
				}
				return
			}
			m.Log.Warn("hypervisor channel: accept failed", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(acceptRetry):
			}
			continue
		}
		p := newPeer(rwc, m.Log, m.deliver, auth.fresh())
		p.onAuthenticated = m.flushHypervisor
		p.onClosed = func() { m.clearHypervisor(p) }
		// Installed before its read loop starts, so a connection that dies at
		// once is cleared by its own onClosed rather than installed afterwards
		// as a dead peer.
		if old := m.setHypervisor(p); old != nil {
			m.Log.Info("hypervisor channel: host reconnected; closing the previous connection")
			if c, ok := old.(io.Closer); ok {
				c.Close()
			}
		} else {
			m.Log.Info("hypervisor channel: host connected")
		}
		current = p
		p.start(ctx)
		m.flushHypervisor() //nolint:contextcheck // the queue outlives any one connection's context
	}
}
