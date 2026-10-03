package transport

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// TestHypervisorLoopback drives the whole channel over an in-process pipe: a
// fake host on one end, core's peer + Mux on the other. Proves inbound frames
// reach a module's Receive stream and outbound Send frames reach the host —
// the mechanism the real virtio-serial/vsock/HvSocket devices only change the
// transport under.
func TestHypervisorLoopback(t *testing.T) {
	guestConn, hostConn := net.Pipe()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mux := &Mux{Log: log}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux.Hypervisor = newHypervisorPeer(ctx, guestConn, log, mux.deliver, authenticatedForTest())

	// A module subscribes to inbound messages.
	in := mux.Receive(ctx, "weave")

	hostR := bufio.NewReader(hostConn)
	hostW := bufio.NewWriter(hostConn)

	// --- Inbound: host -> guest module ---
	go func() {
		_ = hvchannel.WriteEnvelope(hostW, hvchannel.Envelope{
			Module: "weave", Kind: "weave.presence.hello", Data: []byte(`{"id":"h1"}`),
		})
		_ = hostW.Flush()
	}()

	select {
	case msg := <-in:
		if msg.Kind != "weave.presence.hello" {
			t.Fatalf("inbound kind = %q", msg.Kind)
		}
		if msg.Peer != agentv1.Peer_PEER_HYPERVISOR {
			t.Fatalf("inbound peer = %v, want hypervisor", msg.Peer)
		}
		if string(msg.Data) != `{"id":"h1"}` {
			t.Fatalf("inbound data = %s", msg.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inbound message never delivered")
	}

	// --- Outbound: guest module -> host ---
	go func() {
		_, _ = mux.Send(ctx, "weave", agentv1.Peer_PEER_HYPERVISOR,
			"weave.presence.hello.result", []byte(`{"id":"h1","payload":{"os":"linux"}}`), false)
	}()

	done := make(chan hvchannel.Envelope, 1)
	go func() {
		env, err := hvchannel.ReadEnvelope(hostR)
		if err != nil {
			return
		}
		done <- env
	}()

	select {
	case env := <-done:
		if env.Module != "weave" || env.Kind != "weave.presence.hello.result" {
			t.Fatalf("outbound envelope = %+v", env)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outbound frame never reached the host")
	}
}

// TestUndecodableFrameDoesNotKillTheChannel locks the read loop's error
// classification. Reading and decoding are one call now (hvchannel.ReadEnvelope),
// so the loop has to tell a per-message decode failure — the stream is still
// aligned, keep going — from a stream failure, where it must stop. Get that
// backwards and one malformed frame silently ends a channel core cannot
// re-establish, with the guest still apparently healthy.
func TestUndecodableFrameDoesNotKillTheChannel(t *testing.T) {
	guestConn, hostConn := net.Pipe()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mux := &Mux{Log: log}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux.Hypervisor = newHypervisorPeer(ctx, guestConn, log, mux.deliver, authenticatedForTest())
	in := mux.Receive(ctx, "weave")

	hostW := bufio.NewWriter(hostConn)
	go func() {
		// A frame whose payload is not an envelope, then a good one.
		_ = hvchannel.WriteFrame(hostW, []byte("{not json"))
		_ = hvchannel.WriteEnvelope(hostW, hvchannel.Envelope{
			Module: "weave", Kind: "weave.power.shutdown", Data: []byte(`{"id":"p1"}`),
		})
		_ = hostW.Flush()
	}()

	select {
	case msg := <-in:
		if msg.Kind != "weave.power.shutdown" {
			t.Fatalf("kind = %q, want the message after the bad frame", msg.Kind)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the read loop stopped on a malformed frame instead of skipping it")
	}
}

// TestDeliverNoReceiverDoesNotBlock ensures a message for a module with no
// live Receive stream is dropped (logged), never blocking the read loop.
func TestDeliverNoReceiverDoesNotBlock(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mux := &Mux{Log: log}
	done := make(chan struct{})
	go func() {
		mux.deliver("absent", "k", []byte("x"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deliver blocked with no receiver")
	}
}
