package transport

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
)

// TestQueueSurvivesRestart proves the offline queue counter is recovered
// from the store on a new Mux, so a restart does not reset nextID to 1 and
// overwrite still-queued messages.
func TestQueueSurvivesRestart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	queue := hostserv.NewMemStore()

	// First Mux, no host connected: queue two messages.
	m1 := &Mux{Log: log, Queue: queue}
	for _, d := range []string{"a", "b"} {
		if _, err := m1.Send(
			context.Background(),
			"weave-linux-presence",
			agentv1.Peer_PEER_HYPERVISOR,
			"k",
			[]byte(d),
			true,
		); err != nil {
			t.Fatal(err)
		}
	}
	if keys, _ := queue.List(context.Background(), "core.transport", "queue/"); len(keys) != 2 {
		t.Fatalf("after enqueue: %d queued, want 2", len(keys))
	}

	// "Restart": a fresh Mux over the same store queues a third message.
	// If nextID reset to 1 it would overwrite message "a".
	m2 := &Mux{Log: log, Queue: queue}
	if _, err := m2.Send(
		context.Background(),
		"weave-linux-presence",
		agentv1.Peer_PEER_HYPERVISOR,
		"k",
		[]byte("c"),
		true,
	); err != nil {
		t.Fatal(err)
	}
	keys, _ := queue.List(context.Background(), "core.transport", "queue/")
	if len(keys) != 3 {
		t.Fatalf("after restart enqueue: %d queued, want 3 (a message was overwritten)", len(keys))
	}
}

// switchPeer is a host that can go down and come back.
type switchPeer struct {
	recordingPeer
	down bool
}

func (p *switchPeer) Send(ctx context.Context, module, kind string, data []byte) error {
	p.mu.Lock()
	down := p.down
	p.mu.Unlock()
	if down {
		return context.DeadlineExceeded
	}
	return p.recordingPeer.Send(ctx, module, kind, data)
}

func (p *switchPeer) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

func TestSendQueueAndFlush(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	peer := &switchPeer{recordingPeer: recordingPeer{failAfter: -1}}
	queue := hostserv.NewMemStore()
	mux := &Mux{Log: log, Hypervisor: peer, Queue: queue}

	// Delivered while the host is up.
	delivered, err := mux.Send(
		context.Background(),
		"weave-linux-presence",
		agentv1.Peer_PEER_HYPERVISOR,
		"heartbeat",
		[]byte("a"),
		true,
	)
	if err != nil || !delivered {
		t.Fatalf("send: delivered=%v err=%v", delivered, err)
	}

	// Host down: queueOffline queues instead of failing.
	peer.setDown(true)
	delivered, err = mux.Send(
		context.Background(),
		"weave-linux-presence",
		agentv1.Peer_PEER_HYPERVISOR,
		"heartbeat",
		[]byte("b"),
		true,
	)
	if err != nil || delivered {
		t.Fatalf("offline send: delivered=%v err=%v", delivered, err)
	}
	// Without queueOffline the failure is reported.
	if _, err := mux.Send(
		context.Background(),
		"weave-linux-presence",
		agentv1.Peer_PEER_HYPERVISOR,
		"heartbeat",
		[]byte("c"),
		false,
	); err == nil {
		t.Fatal("offline send without queueing reported success")
	}
	if keys, _ := queue.List(context.Background(), "core.transport", "queue/"); len(keys) != 1 {
		t.Fatalf("queue length = %d, want 1", len(keys))
	}

	// Host returns: the next successful send flushes the queue.
	peer.setDown(false)
	delivered, err = mux.Send(
		context.Background(),
		"weave-linux-presence",
		agentv1.Peer_PEER_HYPERVISOR,
		"heartbeat",
		[]byte("d"),
		true,
	)
	if err != nil || !delivered {
		t.Fatalf("recovered send: delivered=%v err=%v", delivered, err)
	}
	// a (first), d (recovery), b (flushed). c was refused, never queued.
	if got := peer.got(); len(got) != 3 || got[0] != "a" || got[1] != "d" || got[2] != "b" {
		t.Fatalf("host received %q, want [a d b]", got)
	}
	if keys, _ := queue.List(context.Background(), "core.transport", "queue/"); len(keys) != 0 {
		t.Fatalf("queue not drained: %v", keys)
	}
}

// TestConcurrentOfflineSendsNoLossNoDup fires many offline sends at once with
// no host connected: the monotonic queue key must not race (no overwrite, no
// loss), and when a host connects every message flushes exactly once (no
// double delivery under the flush mutex).
func TestConcurrentOfflineSendsNoLossNoDup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	queue := hostserv.NewMemStore()
	mux := &Mux{Log: log, Queue: queue}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = mux.Send(
				context.Background(),
				"weave-linux-presence",
				agentv1.Peer_PEER_HYPERVISOR,
				"heartbeat",
				[]byte{byte(i)},
				true,
			)
		}(i)
	}
	wg.Wait()

	keys, _ := queue.List(context.Background(), "core.transport", "queue/")
	if len(keys) != n {
		t.Fatalf(
			"queued %d messages, want %d (a racing key overwrote or dropped one)",
			len(keys),
			n,
		)
	}

	peer := &recordingPeer{failAfter: -1}
	mux.Hypervisor = peer
	var fw sync.WaitGroup
	for range 4 {
		fw.Add(1)
		go func() { defer fw.Done(); mux.Flush(context.Background()) }()
	}
	fw.Wait()

	if got := len(peer.got()); got != n {
		t.Fatalf("host received %d messages, want %d (loss or double delivery)", got, n)
	}
	if keys, _ := queue.List(context.Background(), "core.transport", "queue/"); len(keys) != 0 {
		t.Fatalf("queue not drained after flush: %d left", len(keys))
	}
}
