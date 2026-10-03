package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// pipeListener is a socket channel in memory: each dial hands the accept loop
// one end of a net.Pipe, so the replacement, auth and queue logic runs the same
// on every OS whether or not it has vsock or HvSocket.
type pipeListener struct {
	conns  chan io.ReadWriteCloser
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns:  make(chan io.ReadWriteCloser),
		errs:   make(chan error, 1),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (io.ReadWriteCloser, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// host is the far end of one accepted connection.
type host struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func (l *pipeListener) dial(t *testing.T) *host {
	t.Helper()
	guest, h := net.Pipe()
	t.Cleanup(func() { h.Close() })
	select {
	case l.conns <- guest:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop is not accepting")
	}
	return &host{conn: h, r: bufio.NewReader(h), w: bufio.NewWriter(h)}
}

// authenticate runs the host side of the handshake and reports the result.
func (h *host) authenticate(t *testing.T, priv ed25519.PrivateKey) hvchannel.AuthResult {
	t.Helper()
	send(t, h.w, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(readEnvelope(t, h.r).Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, err := hvchannel.Sign(priv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	send(t, h.w, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)
	var result hvchannel.AuthResult
	env := readEnvelope(t, h.r)
	if env.Kind != hvchannel.KindAuthResult {
		t.Fatalf("expected an auth result, got %q", env.Kind)
	}
	if err := json.Unmarshal(env.Data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// listening starts a socket channel over a pipeListener with a fresh key.
func listening(
	t *testing.T,
	queue hostserv.StoreBackend,
) (*Mux, *pipeListener, ed25519.PrivateKey, context.CancelFunc) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l := newPipeListener()
	useListener(t, func(map[string]string, *slog.Logger) (connListener, error) { return l, nil })
	m := &Mux{Log: quietLog(), Queue: queue}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.ConnectHypervisor(
		ctx,
		map[string]string{"kind": "vsock", "port": "2010"},
		writeKeyFile(t, pub),
	); err != nil {
		t.Fatalf("ConnectHypervisor: %v", err)
	}
	return m, l, priv, cancel
}

func useListener(t *testing.T, fn func(map[string]string, *slog.Logger) (connListener, error)) {
	t.Helper()
	old := listenChannel
	listenChannel = fn
	t.Cleanup(func() { listenChannel = old })
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (m *Mux) hypervisorPeer() Peer { return m.host() }

// A reconnecting host replaces the old connection, which is closed, and starts
// unauthenticated: proof given on the old connection is worth nothing on the
// new one.
func TestReconnectReplacesThePeerAndResetsAuth(t *testing.T) {
	m, l, priv, _ := listening(t, nil)
	in := m.Receive(t.Context(), "weave")

	first := l.dial(t)
	if r := first.authenticate(t, priv); !r.OK {
		t.Fatalf("first host refused: %s", r.Reason)
	}
	firstPeer := m.hypervisorPeer()

	second := l.dial(t)
	eventually(t, "the second connection to take over", func() bool {
		p := m.hypervisorPeer()
		return p != nil && p != firstPeer
	})
	// The first host's connection is closed under it.
	if _, err := first.r.ReadByte(); err == nil {
		t.Fatal("replaced connection still delivers")
	}

	// Unauthenticated: outbound module traffic is refused, inbound is answered
	// with a refusal rather than delivered.
	if ok, err := m.Send(
		t.Context(),
		"weave",
		agentv1.Peer_PEER_HYPERVISOR,
		"weave.exec.output",
		nil,
		false,
	); ok ||
		err == nil {
		t.Fatalf("send before the new host authenticated = %v, %v", ok, err)
	}
	send(t, second.w, "weave", "weave.power.shutdown", nil)
	if env := readEnvelope(t, second.r); env.Kind != hvchannel.KindAuthResult {
		t.Fatalf("gated frame answered with %q, want a refusal", env.Kind)
	}

	if r := second.authenticate(t, priv); !r.OK {
		t.Fatalf("second host refused: %s", r.Reason)
	}
	send(t, second.w, "weave", "weave.power.shutdown", nil)
	select {
	case msg := <-in:
		if msg.Kind != "weave.power.shutdown" {
			t.Fatalf("delivered %q", msg.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated frame never delivered")
	}
}

// Messages sent while no host is connected — or while it has not yet proved
// itself — are queued, and reach the host once it authenticates, in order and
// after the auth result.
func TestQueuedMessagesFlushAfterAuthentication(t *testing.T) {
	queue := hostserv.NewMemStore()
	m, l, priv, _ := listening(t, queue)

	if ok, err := m.Send(
		t.Context(),
		"weave",
		agentv1.Peer_PEER_HYPERVISOR,
		"weave.event",
		[]byte(`"a"`),
		true,
	); ok ||
		err != nil {
		t.Fatalf("send with no host = %v, %v; want queued", ok, err)
	}
	h := l.dial(t)
	eventually(t, "the host to be installed", func() bool { return m.hypervisorPeer() != nil })
	// Connected but unauthenticated: still queued, not lost.
	if ok, err := m.Send(
		t.Context(),
		"weave",
		agentv1.Peer_PEER_HYPERVISOR,
		"weave.event",
		[]byte(`"b"`),
		true,
	); ok ||
		err != nil {
		t.Fatalf("send before auth = %v, %v; want queued", ok, err)
	}
	if n := len(queued(t, queue)); n != 2 {
		t.Fatalf("%d queued before auth, want 2", n)
	}

	if r := h.authenticate(t, priv); !r.OK {
		t.Fatalf("host refused: %s", r.Reason)
	}
	for _, want := range []string{`"a"`, `"b"`} {
		env := readEnvelope(t, h.r)
		if env.Kind != "weave.event" || string(env.Data) != want {
			t.Fatalf("got %s %s, want weave.event %s", env.Kind, env.Data, want)
		}
	}
	eventually(t, "the queue to drain", func() bool { return len(queued(t, queue)) == 0 })
}

// When the current host goes away the peer is cleared, so sends report "not
// connected" (or queue) instead of writing into a dead connection. A replaced
// connection ending must not clear its successor.
func TestHostDisconnectClearsOnlyTheCurrentPeer(t *testing.T) {
	m, l, _, _ := listening(t, nil)

	first := l.dial(t)
	eventually(t, "first host", func() bool { return m.hypervisorPeer() != nil })
	firstPeer := m.hypervisorPeer()
	second := l.dial(t)
	eventually(
		t,
		"second host",
		func() bool { p := m.hypervisorPeer(); return p != nil && p != firstPeer },
	)
	secondPeer := m.hypervisorPeer()
	first.conn.Close()
	// The superseded peer's onClosed has run (its conn was closed at
	// replacement); the successor must still be in place.
	m.clearHypervisor(firstPeer)
	if m.hypervisorPeer() != secondPeer {
		t.Fatal("a superseded connection unplugged its successor")
	}

	second.conn.Close()
	eventually(t, "the peer to clear", func() bool { return m.hypervisorPeer() == nil })
	_, err := m.Send(t.Context(), "weave", agentv1.Peer_PEER_HYPERVISOR, "k", nil, false)
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("send with no host = %v, want not connected", err)
	}
}

// A failed accept is logged and retried rather than ending the channel.
func TestAcceptFailureIsRetried(t *testing.T) {
	old := acceptRetry
	acceptRetry = time.Millisecond
	t.Cleanup(func() { acceptRetry = old })

	logs := &logBuffer{}
	l := newPipeListener()
	useListener(t, func(map[string]string, *slog.Logger) (connListener, error) { return l, nil })
	m := &Mux{Log: slog.New(slog.NewTextHandler(logs, nil))}
	if err := m.ConnectHypervisor(
		t.Context(),
		map[string]string{"kind": "vsock", "port": "1"},
		filepath.Join(t.TempDir(), "nokey"),
	); err != nil {
		t.Fatal(err)
	}
	l.errs <- errors.New("transient")
	eventually(
		t,
		"the accept failure to be logged",
		func() bool { return strings.Contains(logs.String(), "accept failed") },
	)
	l.dial(t)
	eventually(
		t,
		"a connection after the failed accept",
		func() bool { return m.hypervisorPeer() != nil },
	)
}

// A failure while core is stopping waits out the retry on ctx, not the clock.
func TestAcceptRetryStopsWithTheContext(t *testing.T) {
	old := acceptRetry
	acceptRetry = time.Hour
	t.Cleanup(func() { acceptRetry = old })
	l := newPipeListener()
	m := &Mux{Log: quietLog()}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { m.serveHypervisor(ctx, l, &channelAuth{log: quietLog()}); close(done) }()
	l.errs <- errors.New("transient")
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop sat out its retry after the context ended")
	}
}

// Stopping core closes the listener and the live connection.
func TestStopClosesListenerAndConnection(t *testing.T) {
	m, l, _, cancel := listening(t, nil)
	h := l.dial(t)
	eventually(t, "host", func() bool { return m.hypervisorPeer() != nil })
	cancel()
	if _, err := h.r.ReadByte(); err == nil {
		t.Fatal("connection survived core stopping")
	}
	select {
	case <-l.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("listener not closed")
	}
	eventually(t, "the peer to clear", func() bool { return m.hypervisorPeer() == nil })
}

func TestListenFailureIsReported(t *testing.T) {
	useListener(
		t,
		func(map[string]string, *slog.Logger) (connListener, error) { return nil, errChannelAttrs },
	)
	m := &Mux{Log: quietLog()}
	err := m.ConnectHypervisor(
		t.Context(),
		map[string]string{"kind": "vsock", "port": "2010"},
		filepath.Join(t.TempDir(), "nokey"),
	)
	if !errors.Is(err, errChannelAttrs) || !strings.Contains(err.Error(), "listening") {
		t.Fatalf("ConnectHypervisor = %v", err)
	}
	if m.hypervisorPeer() != nil {
		t.Fatal("peer wired despite the listen failure")
	}
}

func TestChannelPort(t *testing.T) {
	if p, err := channelPort(map[string]string{"port": "2010"}); err != nil || p != 2010 {
		t.Fatalf("channelPort = %d, %v", p, err)
	}
	for _, bad := range []string{"", "0", "x", "4294967296"} {
		if _, err := channelPort(map[string]string{"port": bad}); !errors.Is(err, errChannelAttrs) {
			t.Errorf("channelPort(%q) = %v", bad, err)
		}
	}
}

// The service GUID is a wire contract with the host's dialler
// (guestweave-cli-windows hvsock.VsockServiceID): port in Data1, the rest
// fixed.
func TestVsockServiceID(t *testing.T) {
	if got := vsockServiceID(2010); got != "000007da-facb-11e6-bd58-64006a7986d3" {
		t.Fatalf("vsockServiceID(2010) = %s", got)
	}
}
