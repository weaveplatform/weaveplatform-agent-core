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
// every write fails. closed is signalled when the read loop gives up.
type deadWire struct {
	r       io.Reader
	readErr error
	closed  chan struct{}
	once    sync.Once
}

func (w *deadWire) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, w.readErr
	}
	return n, err
}

func (w *deadWire) Write([]byte) (int, error) { return 0, errors.New("wire cut") }

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

// A reply that cannot be written, and then a stream that fails, are both
// logged and end with the connection closed rather than a spinning loop.
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
		readErr: errors.New("device gone"),
		closed:  make(chan struct{}),
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
	for _, want := range []string{"sending a control reply", "unknown control frame", "read ended", "device gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
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
	if _, err := os.Stat(DefaultChannelKeyPath()); err != nil && a.trusted != nil {
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
