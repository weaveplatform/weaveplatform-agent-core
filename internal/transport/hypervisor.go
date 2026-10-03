package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// The hypervisor channel is a single byte pipe (virtio-serial / vsock /
// HvSocket) between core inside the guest and the host/CLI. Core owns exactly
// one connection: the frame protocol has NO resynchronisation, so a second
// reader on the same wire desynchronises it permanently rather than degrading.
// One fd, one read loop, one write mutex — always. On a socket channel "one" is
// over time, not just at once: each new host connection replaces the last
// (hypervisor_listen.go) rather than running beside it.
//
// The framing and addressing format itself lives in
// internal/protocol/hvchannel, kept identical to the sdk's hvchannel that the
// host end imports, because the host end of this wire must encode
// identically and nothing on the channel would detect a mismatch. Core
// translates between hvchannel envelopes and the module-facing (module, kind,
// data) Transport primitives; modules never see framing or device nodes.

// errNotAuthenticated refuses module traffic on a channel whose peer has not
// proved it holds this VM's key.
var errNotAuthenticated = errors.New("transport: hypervisor channel is not authenticated")

// HypervisorPeer implements Peer over a single owned connection.
type HypervisorPeer struct {
	log     *slog.Logger
	deliver func(module, kind string, data []byte)

	conn io.Closer
	r    *bufio.Reader
	wmu  sync.Mutex // single writer
	w    *bufio.Writer

	// auth gates the wire in both directions until the peer has proved it holds
	// this VM's key. Never nil: an unprovisioned guest gets one that refuses
	// everything, because failing closed is the point.
	auth *channelAuth

	// onAuthenticated runs on the read loop once the peer has authenticated,
	// after the result frame is on the wire; onClosed runs when the read loop
	// has ended and the connection is closed. Either may be nil.
	onAuthenticated func()
	onClosed        func()
}

// ConnectHypervisor wires the probed hypervisor channel as the
// PEER_HYPERVISOR peer for the life of ctx. Call once at startup when the
// hypervisor.channel capability is present. attrs is that capability's probe
// attribute map. keyPath is the trusted channel key; empty takes
// DefaultChannelKeyPath.
//
// A device channel (virtio-serial: attrs carry no port) is opened and owned
// for good. A socket channel (attrs carry a port, or kind unix) is listened on
// instead, because on vsock, HvSocket and a container's socket the host dials
// the guest; see
// serveHypervisor for what each new connection does to the previous one.
func (m *Mux) ConnectHypervisor(
	ctx context.Context,
	attrs map[string]string,
	keyPath string,
) error {
	if attrs["port"] != "" || attrs["kind"] == unixKind {
		return m.listenHypervisor(ctx, attrs, keyPath)
	}
	rwc, err := openDevice(attrs)
	if err != nil {
		return fmt.Errorf("transport: opening hypervisor channel: %w", err)
	}
	p := newPeer(rwc, m.Log, m.deliver, newChannelAuth(m.Log, keyPath))
	p.onAuthenticated = m.flushHypervisor
	m.setHypervisor(p)
	p.start(ctx)
	// Drain anything queued while the channel was down. Before authentication
	// this only gets as far as the first gated message; onAuthenticated
	// drains the rest.
	m.Flush(context.WithoutCancel(ctx))
	return nil
}

// flushHypervisor drains the offline queue once a peer has authenticated.
//
// Without it, messages queued because the peer had not yet proved itself
// would sit until some module happened to send again, since only a successful
// Send triggers a flush. It runs on its own goroutine: the read loop calls it,
// and a flush that blocked on a full wire while the host blocked writing to
// us would deadlock the channel.
func (m *Mux) flushHypervisor() {
	go m.Flush(context.Background())
}

// newHypervisorPeer wraps an already-open connection and starts the single
// read loop. Exposed for the loopback test; production goes via
// Mux.ConnectHypervisor.
func newHypervisorPeer(
	ctx context.Context,
	rwc io.ReadWriteCloser,
	log *slog.Logger,
	deliver func(module, kind string, data []byte),
	auth *channelAuth,
) *HypervisorPeer {
	p := newPeer(rwc, log, deliver, auth)
	p.start(ctx)
	return p
}

func newPeer(
	rwc io.ReadWriteCloser,
	log *slog.Logger,
	deliver func(module, kind string, data []byte),
	auth *channelAuth,
) *HypervisorPeer {
	return &HypervisorPeer{
		log:     log,
		deliver: deliver,
		conn:    rwc,
		r:       bufio.NewReader(rwc),
		w:       bufio.NewWriter(rwc),
		auth:    auth,
	}
}

// start runs the read loop. The hooks must be set before it is called.
func (p *HypervisorPeer) start(ctx context.Context) { go p.readLoop(ctx) }

// Close closes the connection, which ends the read loop.
func (p *HypervisorPeer) Close() error { return p.conn.Close() } //nolint:wrapcheck // the conn's own error is the useful one

// Send implements Peer: one addressed frame, written under the single-writer
// mutex.
//
// Outbound is gated too, not just inbound. A module's unsolicited events — exec
// output, file chunks — would otherwise stream to a peer that never proved who it
// was, which would make the inbound gate decorative: an attacker who cannot ask a
// question but can read every answer has most of what they wanted.
func (p *HypervisorPeer) Send(_ context.Context, module, kind string, data []byte) error {
	if !p.auth.allows(kind) {
		return fmt.Errorf("%w; %q not sent", errNotAuthenticated, kind)
	}
	return p.send(module, kind, data)
}

// send writes without the authentication check. Only the handshake itself may use
// it — the frames that establish the authentication cannot be gated on it.
func (p *HypervisorPeer) send(module, kind string, data []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if err := hvchannel.WriteEnvelope(
		p.w,
		hvchannel.Envelope{Module: module, Kind: kind, Data: data},
	); err != nil {
		return fmt.Errorf("transport: writing %q: %w", kind, err)
	}
	if err := p.w.Flush(); err != nil {
		return fmt.Errorf("transport: flushing %q: %w", kind, err)
	}
	return nil
}

// readLoop is the sole reader of the wire. It decodes each frame and fans it
// out to the addressed module's receivers via deliver, until the connection
// errors or ctx ends.
func (p *HypervisorPeer) readLoop(ctx context.Context) {
	defer func() {
		p.conn.Close()
		if p.onClosed != nil {
			p.onClosed()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		env, err := hvchannel.ReadEnvelope(p.r)
		if err != nil {
			// An undecodable envelope costs one message, not the channel: the
			// length prefix has already kept the reader aligned, so carry on.
			// Only a stream-level failure ends the loop.
			if isFrameDecodeError(err) {
				p.log.Warn("hypervisor channel: undecodable frame", "err", err)
				continue
			}
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				p.log.Warn("hypervisor channel read ended", "err", err)
			}
			return
		}
		// Control frames are the channel's own business and never reach a
		// module. Handled before the gate below, because they ARE the gate.
		if env.Module == hvchannel.ControlModule {
			wasOK := p.auth.authenticated()
			if kind, reply := p.auth.handle(env.Kind, env.Data); kind != "" {
				p.reply(kind, reply)
			}
			if !wasOK && p.auth.authenticated() && p.onAuthenticated != nil {
				p.onAuthenticated()
			}
			continue
		}
		if !p.auth.allows(env.Kind) {
			// Say so rather than dropping in silence: an operator whose key is
			// wrong should see a refusal, not a hang that looks like a guest
			// with no agent in it.
			p.log.Warn("hypervisor channel: refusing an operation on an unauthenticated channel",
				"module", env.Module, "kind", env.Kind)
			p.reply(
				hvchannel.KindAuthResult,
				hvchannel.AuthResult{Reason: "channel is not authenticated"},
			)
			continue
		}
		p.deliver(env.Module, env.Kind, env.Data)
	}
}

// reply sends one control frame from the read loop.
func (p *HypervisorPeer) reply(kind string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		p.log.Error("hypervisor channel: encoding a control reply", "kind", kind, "err", err)
		return
	}
	if err := p.send(hvchannel.ControlModule, kind, data); err != nil {
		p.log.Warn("hypervisor channel: sending a control reply", "kind", kind, "err", err)
	}
}

// isFrameDecodeError reports whether err is a per-message decode failure (the
// stream is still aligned) rather than a stream failure (it is not). Framing
// errors wrap a *json.SyntaxError or *json.UnmarshalTypeError; I/O errors do
// not.
func isFrameDecodeError(err error) bool {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &typeErr)
}
