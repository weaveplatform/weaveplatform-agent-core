// Package transport is core's channel mux: modules address a peer, core
// routes. The one peer is the host channel — the authenticated link to
// whatever drives this machine from directly outside it (a hypervisor over
// virtio-serial, vsock or HvSocket; a container runtime over a unix socket).
// Messages a module marks queue_offline wait in a queue persisted in the
// store while no host is connected, and drain when one authenticates.
package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

// queueNamespace is the core-owned store namespace for the offline queue.
const queueNamespace = "core.transport"

// Peer is one channel to somewhere.
type Peer interface {
	// Send delivers one message now or returns an error.
	Send(ctx context.Context, module, kind string, data []byte) error
}

// Mux implements hostserv.TransportBackend over registered peers.
type Mux struct {
	Log *slog.Logger
	// Hypervisor is the host channel peer; nil while no host is connected. ConnectHypervisor
	// owns it once called: a socket channel swaps it on every reconnect, so
	// it is read and written under peerMu from then on.
	Hypervisor Peer
	peerMu     sync.Mutex
	// Queue persists undeliverable queue_offline messages; nil disables.
	Queue hostserv.StoreBackend
	// MaxQueued bounds the offline queue by message count; 0 gets a
	// default. Over the cap, the oldest queued message is dropped.
	MaxQueued int
	// Registry is the installed-module table: it says why a frame could not
	// be delivered, and it is what the host channel's modules.list and
	// modules.changed report. Nil reports every address without a receiver
	// as not installed and an empty module list; core always sets it.
	Registry *registry.Registry

	mu      sync.Mutex
	nextID  uint64
	seeded  bool
	flushMu sync.Mutex // serializes flush so concurrent sends don't double-deliver
	dropped uint64

	subMu sync.Mutex // guards subs
	// subs maps a module id to its live Receive channels; the hypervisor
	// read loop fans inbound messages out through deliver.
	subs map[string][]chan *agentv1.TransportMessage
}

const defaultMaxQueued = 10000

func (m *Mux) maxQueued() int {
	if m.MaxQueued > 0 {
		return m.MaxQueued
	}
	return defaultMaxQueued
}

// Dropped returns how many queued messages have been dropped (queue full
// or unparseable), for the control surface.
func (m *Mux) Dropped() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

type queuedMessage struct {
	Module string `json:"module"`
	Peer   int32  `json:"peer"`
	Kind   string `json:"kind"`
	Data   []byte `json:"data"`
}

// Send implements hostserv.TransportBackend.
func (m *Mux) Send(
	ctx context.Context,
	module string,
	peer agentv1.Peer,
	kind string,
	data []byte,
	queueOffline bool,
) (bool, error) {
	if !known(peer) {
		// Refused rather than queued: nothing will ever connect as this
		// peer, so a queued message would sit in the store until the cap
		// evicted it, reported to the module as merely "not yet delivered".
		return false, fmt.Errorf("no such peer %s: %w", peer.String(), werror.ErrProtocol)
	}
	p := m.host()
	if p != nil {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := p.Send(sctx, module, kind, data)
		cancel()
		if err == nil {
			// The drain is the connection's business, not this call's: a
			// caller that gives up must not strand the rest of the queue.
			m.flush(context.WithoutCancel(ctx), p)
			return true, nil
		}
		m.Log.Warn("peer send failed", "peer", peer.String(), "err", err)
	}
	if !queueOffline {
		if p == nil {
			return false, fmt.Errorf(
				"peer %s not connected: %w",
				peer.String(),
				werror.ErrUnavailable,
			)
		}
		return false, fmt.Errorf("peer %s unreachable: %w", peer.String(), werror.ErrUnavailable)
	}
	m.enqueue(context.WithoutCancel(ctx), module, peer, kind, data)
	return false, nil
}

// Receive implements hostserv.TransportBackend. It registers a subscriber for
// the module's inbound messages and delivers whatever the hypervisor peer's
// read loop routes to that module (via deliver), until ctx ends. Multiple
// concurrent Receive streams for one module are allowed; each gets a copy.
func (m *Mux) Receive(ctx context.Context, module string) <-chan *agentv1.TransportMessage {
	ch := make(chan *agentv1.TransportMessage, inboundBuffer)
	m.subMu.Lock()
	if m.subs == nil {
		m.subs = make(map[string][]chan *agentv1.TransportMessage)
	}
	m.subs[module] = append(m.subs[module], ch)
	m.subMu.Unlock()

	go func() {
		<-ctx.Done()
		m.subMu.Lock()
		subs := m.subs[module]
		for i, c := range subs {
			if c == ch {
				m.subs[module] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		m.subMu.Unlock()
		close(ch)
	}()
	return ch
}

// inboundBuffer bounds each subscriber's queue; a consumer slower than this
// drops messages (logged) rather than stalling the single hypervisor read
// loop, which must never block.
const inboundBuffer = 64

// deliver fans an inbound hypervisor message out to every Receive stream for
// the addressed module. Called from the hypervisor peer's read loop. A slow
// or absent subscriber does not block the loop: the send is non-blocking and a
// full/missing channel drops the message with a warning. A message no
// receiver took comes back as the reason, for the peer to tell the host.
func (m *Mux) deliver(module, kind string, data []byte) *hvchannel.DeliveryFailed {
	msg := &agentv1.TransportMessage{Peer: agentv1.Peer_PEER_HYPERVISOR, Kind: kind, Data: data}
	// The sends happen under subMu, not after copying the slice out: a
	// Receive whose context ends closes its channel under the same lock, and
	// a send racing that close would panic the read loop.
	m.subMu.Lock()
	subs := m.subs[module]
	accepted := false
	for _, ch := range subs {
		select {
		case ch <- msg:
			accepted = true
		default:
			m.Log.Warn("inbound hypervisor receiver slow; message dropped",
				"module", module, "kind", kind)
		}
	}
	m.subMu.Unlock()
	switch {
	case accepted:
		return nil
	case len(subs) > 0:
		return &hvchannel.DeliveryFailed{Module: module, Kind: kind, Reason: hvchannel.ReasonBusy}
	}
	m.Log.Warn("inbound hypervisor message for module with no receiver; dropped",
		"module", module, "kind", kind)
	return m.undeliverable(module, kind)
}

// undeliverable explains a message for an address nothing is receiving on.
func (m *Mux) undeliverable(module, kind string) *hvchannel.DeliveryFailed {
	f := &hvchannel.DeliveryFailed{Module: module, Kind: kind, Reason: hvchannel.ReasonNotInstalled}
	if m.Registry == nil {
		return f
	}
	if mod, ok := m.Registry.ByAddress(module); ok {
		f.Reason = hvchannel.ReasonNotRunning
		f.State = string(mod.State)
		f.Detail = mod.Detail
	}
	return f
}

// known reports whether peer names a channel core has. PEER_UNSPECIFIED is
// the default peer, which is the host channel.
func known(peer agentv1.Peer) bool {
	return peer == agentv1.Peer_PEER_HYPERVISOR || peer == agentv1.Peer_PEER_UNSPECIFIED
}

// host returns the connected host channel peer, or nil.
func (m *Mux) host() Peer {
	m.peerMu.Lock()
	defer m.peerMu.Unlock()
	return m.Hypervisor
}

// setHypervisor makes p the hypervisor peer and returns the one it replaced.
func (m *Mux) setHypervisor(p Peer) (old Peer) {
	m.peerMu.Lock()
	defer m.peerMu.Unlock()
	old, m.Hypervisor = m.Hypervisor, p
	return old
}

// clearHypervisor drops p as the hypervisor peer, unless it has already been
// replaced: a superseded connection ending must not unplug its successor.
func (m *Mux) clearHypervisor(p Peer) {
	m.peerMu.Lock()
	defer m.peerMu.Unlock()
	if m.Hypervisor == p {
		m.Hypervisor = nil
	}
}

// seedNextID recovers the queue counter from the store on first use so a
// restart with messages still queued does not reset to 1 and overwrite
// them. Keys are zero-padded, so lexical max is numeric max.
func (m *Mux) seedNextIDLocked(ctx context.Context) {
	if m.seeded || m.Queue == nil {
		m.seeded = true
		return
	}
	m.seeded = true
	keys, err := m.Queue.List(ctx, queueNamespace, "queue/")
	if err != nil {
		return
	}
	for _, k := range keys {
		var n uint64
		if _, err := fmt.Sscanf(k, "queue/%020d", &n); err == nil && n > m.nextID {
			m.nextID = n
		}
	}
}

func (m *Mux) enqueue(
	ctx context.Context,
	module string,
	peer agentv1.Peer,
	kind string,
	data []byte,
) {
	if m.Queue == nil {
		return
	}
	raw, err := json.Marshal(
		queuedMessage{Module: module, Peer: int32(peer), Kind: kind, Data: data},
	)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.seedNextIDLocked(ctx)
	m.nextID++
	key := fmt.Sprintf("queue/%020d", m.nextID)
	m.mu.Unlock()

	if err := m.Queue.Put(ctx, queueNamespace, key, raw); err != nil {
		m.Log.Warn("queueing message failed", "err", err)
		return
	}
	m.enforceCap(ctx)
	m.Log.Debug("message queued offline", "module", module, "kind", kind)
}

// enforceCap drops the oldest queued messages when over the count cap.
func (m *Mux) enforceCap(ctx context.Context) {
	keys, err := m.Queue.List(ctx, queueNamespace, "queue/")
	if err != nil {
		return
	}
	over := len(keys) - m.maxQueued()
	if over <= 0 {
		return
	}
	sort.Strings(keys) // zero-padded → lexical order is age order.
	for _, k := range keys[:over] {
		_ = m.Queue.Delete(ctx, queueNamespace, k)
		m.mu.Lock()
		m.dropped++
		m.mu.Unlock()
	}
	m.Log.Warn("offline queue over cap; dropped oldest", "dropped", over, "cap", m.maxQueued())
}

// flush drains the queue to the host after a successful send, in FIFO
// order. Serialized so two concurrent successful sends can't both drain the
// same message (double delivery).
func (m *Mux) flush(ctx context.Context, p Peer) {
	if m.Queue == nil {
		return
	}
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	keys, err := m.Queue.List(ctx, queueNamespace, "queue/")
	if err != nil || len(keys) == 0 {
		return
	}
	sort.Strings(keys) // FIFO among multiple queued messages.
	for _, key := range keys {
		raw, found, err := m.Queue.Get(ctx, queueNamespace, key)
		if err != nil || !found {
			continue
		}
		var qm queuedMessage
		if err := json.Unmarshal(raw, &qm); err != nil {
			_ = m.Queue.Delete(ctx, queueNamespace, key)
			m.mu.Lock()
			m.dropped++
			m.mu.Unlock()
			continue
		}
		if !known(agentv1.Peer(qm.Peer)) {
			// Queued for a peer this core does not serve (a reserved
			// value in the store). Nothing will ever deliver it.
			_ = m.Queue.Delete(ctx, queueNamespace, key)
			m.mu.Lock()
			m.dropped++
			m.mu.Unlock()
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = p.Send(sctx, qm.Module, qm.Kind, qm.Data)
		cancel()
		if err != nil {
			return // peer went away again; keep the rest queued
		}
		_ = m.Queue.Delete(ctx, queueNamespace, key)
	}
}

// Flush attempts to drain the queue to a host that has become reachable.
// Call when a host connects. No-op while none is.
func (m *Mux) Flush(ctx context.Context) {
	if p := m.host(); p != nil {
		m.flush(ctx, p)
	}
}
