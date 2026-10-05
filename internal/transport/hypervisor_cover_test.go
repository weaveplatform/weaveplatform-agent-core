package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// deadWire replays canned inbound bytes, then fails the stream with readErr;
// every write fails unless writable is set. closed is signalled on the first
// Close.
type deadWire struct {
	r        io.Reader
	readErr  error
	writable bool
	closed   chan struct{}
	once     sync.Once
}

func (w *deadWire) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, w.readErr
	}
	return n, err
}

func (w *deadWire) Write(p []byte) (int, error) {
	if w.writable {
		return len(p), nil
	}
	return 0, errors.New("wire cut")
}

func (w *deadWire) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

func frames(t *testing.T, envs ...hvchannel.Envelope) io.Reader {
	t.Helper()
	var b bytes.Buffer
	for _, e := range envs {
		if err := hvchannel.WriteEnvelope(&b, e); err != nil {
			t.Fatal(err)
		}
	}
	return &b
}

func waitClosed(t *testing.T, w *deadWire) {
	t.Helper()
	select {
	case <-w.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("read loop never closed the connection")
	}
}

// A stream that fails is logged and ends with the connection closed rather
// than a spinning loop; an unknown or undecodable control frame does not end
// it.
func TestReadLoopWireFailures(t *testing.T) {
	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	wire := &deadWire{
		r: frames(
			t,
			hvchannel.Envelope{Module: hvchannel.ControlModule, Kind: hvchannel.KindAuthBegin},
			hvchannel.Envelope{Module: hvchannel.ControlModule, Kind: "no.such.control"},
			hvchannel.Envelope{
				Module: hvchannel.ControlModule,
				Kind:   hvchannel.KindAuthResponse,
				Data:   []byte("{"),
			},
		),
		readErr:  errors.New("device gone"),
		writable: true,
		closed:   make(chan struct{}),
	}
	newHypervisorPeer(
		context.Background(),
		wire,
		log,
		func(string, string, []byte) *hvchannel.DeliveryFailed {
			t.Error("control frames must never reach a module")
			return nil
		},
		&channelAuth{log: log},
	)
	waitClosed(t, wire)

	out := logs.String()
	for _, want := range []string{"unknown control frame", "read ended", "device gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

// A reply that cannot be written resets the channel: the stream may hold
// part of the frame, and a writer that has failed fails every later frame,
// so carrying on would leave a channel that reads and never answers.
func TestWriteFailureResetsChannel(t *testing.T) {
	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	// The read side stays open until the reset: only the failed write may
	// close the wire.
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	wire := &deadWire{r: pr, readErr: io.EOF, closed: make(chan struct{})}
	newHypervisorPeer(context.Background(), wire, log,
		func(string, string, []byte) *hvchannel.DeliveryFailed { return nil },
		&channelAuth{log: log})
	go func() {
		_ = hvchannel.WriteEnvelope(pw,
			hvchannel.Envelope{Module: hvchannel.ControlModule, Kind: hvchannel.KindAuthBegin})
	}()
	waitClosed(t, wire)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "sending a control reply") {
		if time.Now().After(deadline) {
			t.Fatalf("the failed reply was not logged:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out := logs.String(); !strings.Contains(out, "the channel is being reset") {
		t.Fatalf("log lacks the reset:\n%s", out)
	}
}

// A frame that cannot be encoded costs only itself, not the channel.
func TestUnencodableFrameKeepsChannel(t *testing.T) {
	wire := &deadWire{r: strings.NewReader(""), readErr: nil, writable: true,
		closed: make(chan struct{})}
	p := newPeer(wire, quietLog(), nil, authenticatedForTest())
	big := make([]byte, hvchannel.MaxFrameSize)
	if err := p.Send(context.Background(), "m", "k", big); !errors.Is(err, hvchannel.ErrFrameTooLarge) {
		t.Fatalf("oversized send = %v, want ErrFrameTooLarge", err)
	}
	select {
	case <-wire.closed:
		t.Fatal("an oversized frame reset the channel")
	default:
	}
	if err := p.Send(context.Background(), "m", "k", []byte("x")); err != nil {
		t.Fatalf("send after an oversized frame: %v", err)
	}
}

func TestReadLoopStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wire := &deadWire{r: strings.NewReader(""), readErr: io.EOF, closed: make(chan struct{})}
	newHypervisorPeer(ctx, wire, quietLog(), nil, authenticatedForTest())
	waitClosed(t, wire)
}

func TestSendOnBrokenWire(t *testing.T) {
	wire := &deadWire{r: strings.NewReader(""), readErr: io.EOF, closed: make(chan struct{})}
	p := newHypervisorPeer(context.Background(), wire, quietLog(), nil, authenticatedForTest())
	// Large enough to bypass the bufio buffer and hit the wire directly.
	if err := p.Send(context.Background(), "m", "k", make([]byte, 64<<10)); err == nil {
		t.Fatal("large send on a cut wire succeeded")
	}
	if err := p.Send(context.Background(), "m", "k", []byte("x")); err == nil {
		t.Fatal("small send on a cut wire succeeded")
	}
}

func TestLoadChannelKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadChannelKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing key file accepted")
	}
	if _, err := loadChannelKey(
		write("hex", "deadbeef!"),
	); err == nil ||
		!strings.Contains(err.Error(), "not base64") {
		t.Fatalf("non-base64 key: %v", err)
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := loadChannelKey(
		write("short", short),
	); err == nil ||
		!strings.Contains(err.Error(), "16 bytes") {
		t.Fatalf("short key: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadChannelKey(write("ok", "  "+base64.StdEncoding.EncodeToString(pub)+"\n"))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("valid key: %v", err)
	}
}

func TestNewChannelAuthDefaultPath(t *testing.T) {
	logs := &logBuffer{}
	a := newChannelAuth(slog.New(slog.NewTextHandler(logs, nil)), "")
	if !strings.Contains(logs.String(), filepath.Base(DefaultChannelKeyPath())) {
		t.Fatalf("default key path not consulted:\n%s", logs)
	}
	// Test hosts are not provisioned guests; unless one is, nothing is trusted.
	if _, err := os.Stat(DefaultChannelKeyPath()); err != nil && a.anchor.get() != nil {
		t.Fatal("trusted a key that does not exist")
	}
}

func TestDefaultChannelKeyPathUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by the windows test")
	}
	if got := DefaultChannelKeyPath(); got != "/etc/weave/channel.pub" {
		t.Fatalf("DefaultChannelKeyPath() = %q", got)
	}
}

// ConnectHypervisor over a device that is immediately at EOF: the peer is
// wired, the queue flush is attempted, and the read loop ends quietly.
func TestConnectHypervisor(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "vport")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.ConnectHypervisor(
		ctx,
		map[string]string{"device": dev},
		filepath.Join(t.TempDir(), "nokey"),
	); err != nil {
		t.Fatalf("ConnectHypervisor: %v", err)
	}
	if m.Hypervisor == nil {
		t.Fatal("hypervisor peer not wired")
	}
	// Unauthenticated: module traffic is refused outbound.
	if ok, err := m.Send(
		ctx,
		"m",
		agentv1.Peer_PEER_HYPERVISOR,
		"weave.exec",
		nil,
		false,
	); ok ||
		err == nil {
		t.Fatalf("unauthenticated send = %v, %v", ok, err)
	}
}

// loggingWire is a device that reports on its own I/O.
type loggingWire struct {
	*deadWire
	log *slog.Logger
}

func (w *loggingWire) useLog(l *slog.Logger) { w.log = l }

// A device that logs is given the channel's logger before any I/O.
func TestAttachDeviceSharesLogger(t *testing.T) {
	mux := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := &loggingWire{deadWire: &deadWire{
		r: strings.NewReader(""), readErr: io.EOF, writable: true, closed: make(chan struct{}),
	}}
	closed := mux.attachDevice(ctx, wire, authenticatedForTest())
	if wire.log != mux.Log {
		t.Fatal("the device was not given the channel's logger")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop did not end on EOF")
	}
}
