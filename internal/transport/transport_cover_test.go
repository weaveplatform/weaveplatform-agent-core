package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

var errStore = errors.New("store unavailable")

// flakyStore is a MemStore whose individual operations can be made to fail,
// to reach the paths where the offline queue's store misbehaves.
type flakyStore struct {
	hostserv.StoreBackend
	failList, failPut, failGet bool
	missing                    map[string]bool // Get reports not-found
}

func (s *flakyStore) List(ctx context.Context, module, prefix string) ([]string, error) {
	if s.failList {
		return nil, errStore
	}
	return s.StoreBackend.List(ctx, module, prefix)
}

func (s *flakyStore) Put(ctx context.Context, module, key string, v []byte) error {
	if s.failPut {
		return errStore
	}
	return s.StoreBackend.Put(ctx, module, key, v)
}

func (s *flakyStore) Get(ctx context.Context, module, key string) ([]byte, bool, error) {
	if s.failGet {
		return nil, false, errStore
	}
	if s.missing[key] {
		return nil, false, nil
	}
	return s.StoreBackend.Get(ctx, module, key)
}

// recordingPeer records what it was sent and fails once failAfter sends
// have succeeded (negative never fails).
type recordingPeer struct {
	mu        sync.Mutex
	sent      []string
	failAfter int
}

func (p *recordingPeer) Send(_ context.Context, _, _ string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failAfter >= 0 && len(p.sent) >= p.failAfter {
		return errors.New("peer down")
	}
	p.sent = append(p.sent, string(data))
	return nil
}

func (p *recordingPeer) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.sent...)
}

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func queued(t *testing.T, s hostserv.StoreBackend) []string {
	t.Helper()
	keys, err := s.List(context.Background(), queueNamespace, "queue/")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestMaxQueuedDefault(t *testing.T) {
	if got := (&Mux{}).maxQueued(); got != defaultMaxQueued {
		t.Fatalf("maxQueued() = %d, want %d", got, defaultMaxQueued)
	}
}

func TestQueueCapDropsOldest(t *testing.T) {
	q := hostserv.NewMemStore()
	m := &Mux{Log: quietLog(), Queue: q, MaxQueued: 2}
	for _, d := range []string{"a", "b", "c"} {
		if _, err := m.Send(
			context.Background(),
			"mod",
			agentv1.Peer_PEER_HYPERVISOR,
			"k",
			[]byte(d),
			true,
		); err != nil {
			t.Fatal(err)
		}
	}
	if m.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", m.Dropped())
	}
	// The survivors are the two newest, delivered in order once the peer is up.
	p := &recordingPeer{failAfter: -1}
	m.Hypervisor = p
	m.Flush(context.Background())
	if got := p.got(); len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("flushed %q, want [b c]", got)
	}
}

func TestSendWithoutPeerOrQueue(t *testing.T) {
	m := &Mux{Log: quietLog()}
	ok, err := m.Send(context.Background(), "mod", agentv1.Peer_PEER_HYPERVISOR, "k", nil, false)
	if ok || err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("Send = %v, %v", ok, err)
	}
	// queue_offline with no queue configured is accepted and dropped.
	if ok, err := m.Send(
		context.Background(),
		"mod",
		agentv1.Peer_PEER_HYPERVISOR,
		"k",
		nil,
		true,
	); ok ||
		err != nil {
		t.Fatalf("Send(queueOffline, no queue) = %v, %v", ok, err)
	}
	m.Flush(context.Background()) // no peer: no-op
	m.Hypervisor = &recordingPeer{failAfter: -1}
	m.Flush(context.Background()) // peer but no queue: no-op
}

func TestSendToFailingPeerWithoutQueueing(t *testing.T) {
	m := &Mux{Log: quietLog(), Hypervisor: &recordingPeer{failAfter: 0}}
	ok, err := m.Send(context.Background(), "mod", agentv1.Peer_PEER_HYPERVISOR, "k", nil, false)
	if ok || err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("Send = %v, %v", ok, err)
	}
}

func TestEnqueueStoreFailures(t *testing.T) {
	t.Run("put fails", func(t *testing.T) {
		q := &flakyStore{StoreBackend: hostserv.NewMemStore(), failPut: true}
		m := &Mux{Log: quietLog(), Queue: q}
		if _, err := m.Send(
			context.Background(),
			"mod",
			agentv1.Peer_PEER_HYPERVISOR,
			"k",
			nil,
			true,
		); err != nil {
			t.Fatal(err)
		}
		if len(queued(t, q.StoreBackend)) != 0 {
			t.Fatal("message queued though Put failed")
		}
	})

	// A store that cannot list still takes the message: the counter just
	// cannot be recovered, and the cap cannot be enforced this time.
	t.Run("list fails", func(t *testing.T) {
		q := &flakyStore{StoreBackend: hostserv.NewMemStore(), failList: true}
		m := &Mux{Log: quietLog(), Queue: q, MaxQueued: 1}
		for range 2 {
			if _, err := m.Send(
				context.Background(),
				"mod",
				agentv1.Peer_PEER_HYPERVISOR,
				"k",
				nil,
				true,
			); err != nil {
				t.Fatal(err)
			}
		}
		if n := len(queued(t, q.StoreBackend)); n != 2 {
			t.Fatalf("%d queued, want 2", n)
		}
		if m.Dropped() != 0 {
			t.Fatal("dropped without being able to list")
		}
		// flush cannot list either, and must not deliver or delete anything.
		p := &recordingPeer{failAfter: -1}
		m.Hypervisor = p
		m.Flush(context.Background())
		if len(p.got()) != 0 {
			t.Fatal("flush delivered without a listing")
		}
	})
}

func TestFlushSkipsAndDrops(t *testing.T) {
	ctx := context.Background()
	mem := hostserv.NewMemStore()
	q := &flakyStore{StoreBackend: mem, missing: map[string]bool{}}
	m := &Mux{Log: quietLog(), Queue: q}

	send := func(peer agentv1.Peer, d string) {
		t.Helper()
		if _, err := m.Send(ctx, "mod", peer, "k", []byte(d), true); err != nil {
			t.Fatal(err)
		}
	}
	send(agentv1.Peer_PEER_HYPERVISOR, "hv-1")
	// The default peer is the host channel, and drains with it.
	send(agentv1.Peer_PEER_UNSPECIFIED, "default-1")
	send(agentv1.Peer_PEER_HYPERVISOR, "hv-2")
	// An unparseable entry is dropped and counted, not retried forever.
	if err := mem.Put(
		ctx,
		queueNamespace,
		"queue/00000000000000000000",
		[]byte("{not json"),
	); err != nil {
		t.Fatal(err)
	}
	// So is one an earlier core queued for a peer that no longer exists.
	legacy, _ := json.Marshal(
		queuedMessage{Module: "mod", Peer: 1, Kind: "k", Data: []byte("legacy")},
	)
	if err := mem.Put(ctx, queueNamespace, "queue/50000000000000000000", legacy); err != nil {
		t.Fatal(err)
	}
	// An entry that vanished between List and Get is skipped.
	if err := mem.Put(ctx, queueNamespace, "queue/99999999999999999999", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	q.missing["queue/99999999999999999999"] = true

	m.Flush(context.Background()) // no host: no-op
	p := &recordingPeer{failAfter: -1}
	m.Hypervisor = p
	m.Flush(context.Background())

	if got := p.got(); len(got) != 3 || got[0] != "hv-1" || got[1] != "default-1" ||
		got[2] != "hv-2" {
		t.Fatalf("flushed %q, want the three host messages in order", got)
	}
	if m.Dropped() != 2 {
		t.Fatalf("Dropped() = %d, want 2", m.Dropped())
	}
	if n := len(queued(t, mem)); n != 1 { // the vanished one
		t.Fatalf("%d left queued, want 1", n)
	}

	send(agentv1.Peer_PEER_HYPERVISOR, "hv-3") // delivered directly; flush then fails Get
	q.failGet = true
	m.Flush(context.Background())
	if got := p.got(); len(got) != 4 {
		t.Fatalf("delivered %q through a failing Get", got)
	}
}

// A peer name core has no channel for is refused outright, even with
// queue_offline: nothing would ever drain it.
func TestSendToUnknownPeerRefused(t *testing.T) {
	q := hostserv.NewMemStore()
	m := &Mux{Log: quietLog(), Queue: q, Hypervisor: &recordingPeer{failAfter: -1}}
	ok, err := m.Send(context.Background(), "mod", agentv1.Peer(1), "k", nil, true)
	if ok || !errors.Is(err, werror.ErrProtocol) {
		t.Fatalf("Send = %v, %v", ok, err)
	}
	if n := len(queued(t, q)); n != 0 {
		t.Fatalf("%d queued for an unknown peer", n)
	}
}

// A peer that drops mid-flush keeps the rest queued, in order.
func TestFlushStopsWhenPeerFails(t *testing.T) {
	q := hostserv.NewMemStore()
	m := &Mux{Log: quietLog(), Queue: q}
	for _, d := range []string{"a", "b", "c"} {
		if _, err := m.Send(
			context.Background(),
			"mod",
			agentv1.Peer_PEER_HYPERVISOR,
			"k",
			[]byte(d),
			true,
		); err != nil {
			t.Fatal(err)
		}
	}
	p := &recordingPeer{failAfter: 1}
	m.Hypervisor = p
	m.Flush(context.Background())
	if got := p.got(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("flushed %q, want [a]", got)
	}
	if n := len(queued(t, q)); n != 2 {
		t.Fatalf("%d still queued, want 2", n)
	}
}

func TestDeliverToSlowReceiverDoesNotBlock(t *testing.T) {
	m := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := m.Receive(ctx, "mod")
	for range inboundBuffer + 5 {
		m.deliver("mod", "k", nil)
	}
	if len(in) != inboundBuffer {
		t.Fatalf("buffered %d, want %d", len(in), inboundBuffer)
	}
}
