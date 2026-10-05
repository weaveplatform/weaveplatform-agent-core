package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

func setFrameStall(t *testing.T, d time.Duration) {
	t.Helper()
	orig := frameStall
	frameStall = d
	t.Cleanup(func() { frameStall = orig })
}

func frameBytes(t *testing.T, env hvchannel.Envelope) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := hvchannel.WriteEnvelope(&b, env); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The watch follows frame boundaries however the bytes are split, including
// an empty frame, and reports a stall only inside a frame.
func TestFrameWatchFollowsBoundaries(t *testing.T) {
	var stream bytes.Buffer
	for _, n := range []int{5, 0, 70000, 1} {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(n))
		stream.Write(hdr[:])
		stream.Write(make([]byte, n))
	}
	all := stream.Bytes()
	for _, step := range []int{1, 3, 7, 4096, len(all)} {
		w := newFrameWatch(bytes.NewReader(all))
		buf := make([]byte, step)
		for {
			if _, err := w.Read(buf); err != nil {
				break
			}
		}
		if ok, info := w.stalled(0); ok || w.hdrHave != 0 || info.total != uint64(len(all)) {
			t.Fatalf("step %d: ended mid-frame %+v (hdrHave %d)", step, info, w.hdrHave)
		}
	}

	w := newFrameWatch(bytes.NewReader(append(all, 0, 0, 1, 0, 9, 9)))
	if _, err := io.ReadAll(w); err != nil {
		t.Fatal(err)
	}
	ok, info := w.stalled(0)
	if !ok || info.declared != 256 || info.missing != 254 {
		t.Fatalf("partial body: stalled=%v %+v", ok, info)
	}
	if ok, _ := w.stalled(time.Hour); ok {
		t.Fatal("a recent byte is not a stall")
	}
	w = newFrameWatch(bytes.NewReader([]byte{0, 0}))
	if _, err := io.ReadAll(w); err != nil {
		t.Fatal(err)
	}
	if ok, info := w.stalled(0); !ok || info.missing != 2 || info.declared != 0 {
		t.Fatalf("partial header: stalled=%v %+v", ok, info)
	}
}

// A frame that stops part-way ends the read loop instead of leaving it
// waiting for bytes that will never come, and says why.
func TestPeerResetsAStalledFrame(t *testing.T) {
	setFrameStall(t, 40*time.Millisecond)
	host, guest := net.Pipe()
	defer host.Close()
	var logs logBuffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	p := newPeer(
		guest,
		log,
		func(string, string, []byte) *hvchannel.DeliveryFailed { return nil },
		authenticatedForTest(),
	)
	closed := make(chan struct{})
	p.onClosed = func() { close(closed) }
	p.start(context.Background())

	whole := frameBytes(t, hvchannel.Envelope{Module: "m", Kind: "k", Data: make([]byte, 1000)})
	go host.Write(whole[:300]) //nolint:errcheck // the stall is the point
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled frame kept the read loop waiting")
	}
	if s := logs.String(); !strings.Contains(s, "stalled part-way") ||
		!strings.Contains(s, `"missing_bytes":`) {
		t.Fatalf("log: %s", s)
	}
}

// Idle between frames is not a stall.
func TestPeerIdleBetweenFramesIsNotAStall(t *testing.T) {
	setFrameStall(t, 20*time.Millisecond)
	host, guest := net.Pipe()
	defer host.Close()
	got := make(chan string, 2)
	p := newPeer(guest, quietLog(), func(_, kind string, _ []byte) *hvchannel.DeliveryFailed {
		got <- kind
		return nil
	}, authenticatedForTest())
	closed := make(chan struct{})
	p.onClosed = func() { close(closed) }
	p.start(context.Background())
	for _, kind := range []string{"one", "two"} {
		if _, err := host.Write(
			frameBytes(t, hvchannel.Envelope{Module: "m", Kind: kind}),
		); err != nil {
			t.Fatal(err)
		}
		if k := <-got; k != kind {
			t.Fatalf("delivered %q", k)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("an idle channel was reset")
	default:
	}
	p.Close()
}

// fakeDevices hands out net.Pipe guest ends as successive opens of the device,
// failing the opens it is told to.
type fakeDevices struct {
	mu    sync.Mutex
	fail  int
	hosts chan net.Conn
	opens int
}

func (d *fakeDevices) open(attrs map[string]string) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opens++
	if attrs["device"] == "" {
		return nil, errors.New("no device")
	}
	if d.fail > 0 && d.opens > 1 {
		d.fail--
		return nil, errors.New("device busy")
	}
	host, guest := net.Pipe()
	d.hosts <- host
	return guest, nil
}

// A device channel whose stream breaks is opened again, starts
// unauthenticated, and carries frames: the channel heals without core
// restarting. An open that fails is retried.
func TestDeviceChannelReopensAfterAStall(t *testing.T) {
	setFrameStall(t, 40*time.Millisecond)
	devs := &fakeDevices{fail: 1, hosts: make(chan net.Conn, 4)}
	origOpen, origDelay := openChannelDevice, reopenDelay
	openChannelDevice, reopenDelay = devs.open, 10*time.Millisecond
	t.Cleanup(func() { openChannelDevice, reopenDelay = origOpen, origDelay })

	var logs logBuffer
	m := &Mux{Log: slog.New(slog.NewJSONHandler(&logs, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.ConnectHypervisor(
		ctx,
		map[string]string{"device": "/dev/fake"},
		"/nonexistent/key",
	); err != nil {
		t.Fatal(err)
	}
	first := <-devs.hosts
	first.Write(
		[]byte{0, 0, 1},
	) //nolint:errcheck // a header cut short: the stream has lost its place
	var second net.Conn
	select {
	case second = <-devs.hosts:
	case <-time.After(5 * time.Second):
		t.Fatalf("the device was not reopened: %s", logs.String())
	}
	defer second.Close()

	// The new connection answers: an unauthenticated module frame is refused
	// with an auth.result, which only a live read loop sends.
	go second.Write(
		frameBytes(t, hvchannel.Envelope{Module: "weave.exec", Kind: "weave.exec.start", ID: "x"}),
	) //nolint:errcheck
	reply, err := hvchannel.ReadEnvelope(second)
	if err != nil || reply.Kind != hvchannel.KindAuthResult || reply.ID != "x" {
		t.Fatalf("reply %+v, %v", reply, err)
	}
	if s := logs.String(); !strings.Contains(s, "device reopened") ||
		!strings.Contains(s, "device busy") {
		t.Fatalf("log: %s", s)
	}
	if m.host() == nil {
		t.Fatal("no peer after the reopen")
	}

	// Ending ctx stops the loop rather than reopening again.
	cancel()
	time.Sleep(50 * time.Millisecond)
	devs.mu.Lock()
	opens := devs.opens
	devs.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	devs.mu.Lock()
	defer devs.mu.Unlock()
	if devs.opens != opens {
		t.Fatal("reopened after ctx ended")
	}
}

// The context ending while the reopen waits ends the loop too.
func TestDeviceReopenStopsWithContext(t *testing.T) {
	devs := &fakeDevices{fail: 1 << 30, hosts: make(chan net.Conn, 4)}
	origOpen, origDelay := openChannelDevice, reopenDelay
	openChannelDevice, reopenDelay = devs.open, time.Millisecond
	t.Cleanup(func() { openChannelDevice, reopenDelay = origOpen, origDelay })
	m := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.ConnectHypervisor(ctx, map[string]string{"device": "/dev/fake"}, ""); err != nil {
		t.Fatal(err)
	}
	(<-devs.hosts).Close() // the stream ends; every reopen now fails
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)
	devs.mu.Lock()
	opens := devs.opens
	devs.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	devs.mu.Lock()
	defer devs.mu.Unlock()
	if opens < 2 || devs.opens != opens {
		t.Fatalf("opens %d then %d", opens, devs.opens)
	}
}
