package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

func setInboundWait(t *testing.T, d time.Duration) {
	t.Helper()
	orig := inboundWait
	inboundWait = d
	t.Cleanup(func() { inboundWait = orig })
}

func fill(t *testing.T, m *Mux, module string) {
	t.Helper()
	for range inboundBuffer {
		if f := m.deliver(module, "k", nil); f != nil {
			t.Fatalf("delivery into a queue with room failed: %+v", f)
		}
	}
}

// A full receiver holds the delivery until it makes room, and the message is
// delivered rather than dropped.
func TestDeliverWaitsForRoom(t *testing.T) {
	setInboundWait(t, time.Minute)
	m := &Mux{Log: quietLog()}
	in := m.Receive(t.Context(), "mod")
	fill(t, m, "mod")

	done := make(chan *hvchannel.DeliveryFailed, 1)
	go func() { done <- m.deliver("mod", "last", nil) }()
	select {
	case f := <-done:
		t.Fatalf("delivery into a full queue returned at once: %+v", f)
	case <-time.After(50 * time.Millisecond):
	}
	<-in
	if f := <-done; f != nil {
		t.Fatalf("delivery once there was room failed: %+v", f)
	}
	for range inboundBuffer - 1 {
		<-in
	}
	if msg := <-in; msg.GetKind() != "last" {
		t.Fatalf("last message = %q", msg.GetKind())
	}
}

// A receiver that never makes room costs the channel inboundWait, not more,
// and the host is told busy.
func TestDeliverGivesUpOnAStuckReceiver(t *testing.T) {
	setInboundWait(t, 30*time.Millisecond)
	var logs logBuffer
	m := &Mux{Log: slog.New(slog.NewJSONHandler(&logs, nil))}
	m.Receive(t.Context(), "mod")
	m.Receive(t.Context(), "mod")
	fill(t, m, "mod")
	start := time.Now()
	f := m.deliver("mod", "k", nil)
	if f == nil || f.Reason != hvchannel.ReasonBusy {
		t.Fatalf("failure = %+v", f)
	}
	// One deadline for the frame: two stuck receivers do not wait twice.
	if took := time.Since(start); took < 30*time.Millisecond || took > time.Second {
		t.Fatalf("gave up after %s", took)
	}
	if !strings.Contains(logs.String(), "receiver stuck") {
		t.Fatalf("log: %s", logs.String())
	}
}

// One receiver with room takes the message even when another is stuck.
func TestDeliverToOneOfTwoReceivers(t *testing.T) {
	setInboundWait(t, 10*time.Millisecond)
	m := &Mux{Log: quietLog()}
	m.Receive(t.Context(), "mod")
	fill(t, m, "mod")
	fresh := m.Receive(t.Context(), "mod")
	if f := m.deliver("mod", "k", nil); f != nil {
		t.Fatalf("failure = %+v", f)
	}
	if len(fresh) != 1 {
		t.Fatalf("the receiver with room got %d", len(fresh))
	}
}

// A receiver whose stream ends while a delivery waits on it releases the
// delivery at once, and the close does not race the send.
func TestDeliverStopsWaitingWhenTheReceiverEnds(t *testing.T) {
	setInboundWait(t, time.Minute)
	m := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(context.Background())
	m.Receive(ctx, "mod")
	fill(t, m, "mod")
	done := make(chan *hvchannel.DeliveryFailed, 1)
	go func() { done <- m.deliver("mod", "k", nil) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case f := <-done:
		if f == nil || f.Reason != hvchannel.ReasonBusy {
			t.Fatalf("failure = %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delivery kept waiting on a receiver that had gone")
	}
	// Once its stream is gone, the module has no receiver at all.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if f := m.deliver("mod", "k", nil); f != nil && f.Reason == hvchannel.ReasonNotInstalled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ended stream stayed registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A closed subscriber refuses an offer without touching its channel.
func TestOfferToAClosedSubscriber(t *testing.T) {
	s := &subscriber{ch: make(chan *agentv1.TransportMessage, 1), done: make(chan struct{})}
	s.close()
	if s.offer(nil, time.Second) {
		t.Fatal("a closed subscriber took a message")
	}
}

// The stall watch is held while a delivery waits: bytes of the next frame the
// decoder already buffered are not read from the wire meanwhile, and that
// silence is the read loop's, not a lost byte's.
func TestFrameWatchHeld(t *testing.T) {
	w := newFrameWatch(strings.NewReader("\x00\x00\x01\x00ab"))
	buf := make([]byte, 16)
	if _, err := w.Read(buf); err != nil {
		t.Fatal(err)
	}
	w.hold()
	if ok, _ := w.stalled(0); ok {
		t.Fatal("a held watch reported a stall")
	}
	w.release()
	if ok, _ := w.stalled(time.Hour); ok {
		t.Fatal("release did not restart the clock")
	}
	if ok, _ := w.stalled(0); !ok {
		t.Fatal("a released watch stopped seeing a partial frame")
	}
}

// End to end over the peer: a host streaming far more than the receive queue
// holds, to a module that reads slowly, has every frame delivered in order and
// none refused — and a delivery wait longer than the stall limit, with the next
// frame half read, does not reset the channel.
func TestPeerAppliesBackpressure(t *testing.T) {
	setFrameStall(t, 40*time.Millisecond)
	setInboundWait(t, 10*time.Second)
	host, guest := net.Pipe()
	defer host.Close()
	var logs logBuffer
	m := &Mux{Log: slog.New(slog.NewJSONHandler(&logs, nil))}
	in := m.Receive(t.Context(), "weave.exec")
	p := newPeer(guest, m.Log, m.deliver, authenticatedForTest())
	closed := make(chan struct{})
	p.onClosed = func() { close(closed) }
	p.start(t.Context())

	const frames = 3 * inboundBuffer
	var wg sync.WaitGroup
	wg.Go(func() {
		// Each write ends half-way through the next frame, so whenever a
		// delivery waits the decoder already holds part of the next one.
		var stream []byte
		for i := range frames {
			stream = append(stream, frameBytes(t, hvchannel.Envelope{
				Module: "weave.exec", Kind: "weave.exec.stdin", Data: fmt.Appendf(nil, "%d", i),
			})...)
		}
		step := len(stream) / frames
		for off := 0; off < len(stream); off += step {
			if _, err := host.Write(stream[off:min(off+step+step/2, len(stream))]); err != nil {
				return
			}
			off += step / 2
		}
	})
	// Not read at all until well past the stall limit: the queue fills and the
	// read loop waits with a frame half read.
	time.Sleep(200 * time.Millisecond)
	for i := range frames {
		select {
		case msg := <-in:
			if want := fmt.Sprintf("%d", i); string(msg.GetData()) != want {
				t.Fatalf("frame %d carried %s", i, msg.GetData())
			}
		case <-closed:
			t.Fatalf("channel reset at frame %d: %s", i, logs.String())
		case <-time.After(10 * time.Second):
			t.Fatalf("frame %d never arrived", i)
		}
	}
	wg.Wait()
	select {
	case <-closed:
		t.Fatalf("channel reset: %s", logs.String())
	default:
	}
	if s := logs.String(); strings.Contains(s, "stuck") || strings.Contains(s, "dropped") {
		t.Fatalf("log: %s", s)
	}
}
