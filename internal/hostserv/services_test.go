package hostserv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

var errBoom = errors.New("boom")

// sendStream is a server-streaming fake: it records what the handler sends
// and can be told to fail a send, which a real client cannot be made to do
// on demand.
type sendStream[T any] struct {
	grpc.ServerStream
	ctx     context.Context
	mu      sync.Mutex
	sent    []*T
	sendErr error
	onSend  func(n int)
}

func (s *sendStream[T]) Context() context.Context { return s.ctx }

func (s *sendStream[T]) Send(m *T) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.mu.Lock()
	s.sent = append(s.sent, m)
	n := len(s.sent)
	s.mu.Unlock()
	if s.onSend != nil {
		s.onSend(n)
	}
	return nil
}

func (s *sendStream[T]) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

// recvStream is a client-streaming fake: it yields recs, then ends with
// endErr (io.EOF for a normal close).
type recvStream[Req, Resp any] struct {
	grpc.ServerStream
	recs   []*Req
	endErr error
	closed *Resp
}

func (s *recvStream[Req, Resp]) Context() context.Context { return context.Background() }

func (s *recvStream[Req, Resp]) Recv() (*Req, error) {
	if len(s.recs) == 0 {
		return nil, s.endErr
	}
	r := s.recs[0]
	s.recs = s.recs[1:]
	return r, nil
}

func (s *recvStream[Req, Resp]) SendAndClose(r *Resp) error {
	s.closed = r
	return nil
}

type errStore struct{}

func (errStore) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, werror.ErrNotFound
}
func (errStore) Put(context.Context, string, string, []byte) error { return werror.ErrUnavailable }
func (errStore) Delete(context.Context, string, string) error      { return werror.ErrDenied }
func (errStore) List(context.Context, string, string) ([]string, error) {
	return nil, werror.ErrProtocol
}

// scriptedPolicy returns docs in order, one per Get, and lets the test
// drive the change channel.
type scriptedPolicy struct {
	mu      sync.Mutex
	docs    [][]byte
	getErr  error
	changes chan struct{}
}

func (p *scriptedPolicy) Get(context.Context, string) (uint64, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.getErr != nil {
		return 0, nil, p.getErr
	}
	d := p.docs[0]
	if len(p.docs) > 1 {
		p.docs = p.docs[1:]
	}
	return 1, d, nil
}

func (p *scriptedPolicy) Watch(context.Context, string) <-chan struct{} { return p.changes }

type fakeIdentity struct{ err error }

func (fakeIdentity) WhoAmI(context.Context) (string, bool, string) { return "dev-1", false, "acme" }

func (f fakeIdentity) Credential(
	_ context.Context,
	module string,
	scopes []string,
) (string, int64, []string, error) {
	if f.err != nil {
		return "", 0, nil, f.err
	}
	return "tok-" + module, 42, scopes, nil
}

type fakeTransport struct {
	sendErr error
	inbound chan *agentv1.TransportMessage
	got     []string
}

func (f *fakeTransport) Send(
	_ context.Context,
	module string,
	peer agentv1.Peer,
	kind string,
	data []byte,
	queue bool,
) (bool, error) {
	f.got = append(f.got, fmt.Sprintf("%s/%v/%s/%s/%v", module, peer, kind, data, queue))
	return f.sendErr == nil, f.sendErr
}

func (f *fakeTransport) Receive(context.Context, string) <-chan *agentv1.TransportMessage {
	return f.inbound
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestGRPCErrMapsSentinelsToWireCodes(t *testing.T) {
	if grpcErr(nil) != nil {
		t.Fatal("nil error must stay nil")
	}
	cases := map[error]codes.Code{
		werror.ErrNotFound:                            codes.NotFound,
		werror.ErrUnavailable:                         codes.Unavailable,
		werror.ErrDenied:                              codes.PermissionDenied,
		werror.ErrProtocol:                            codes.FailedPrecondition,
		fmt.Errorf("wrapped: %w", werror.ErrNotFound): codes.NotFound,
		errBoom: codes.Internal,
	}
	for in, want := range cases {
		if got := status.Code(grpcErr(in)); got != want {
			t.Errorf("grpcErr(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestTopicAllowed(t *testing.T) {
	allow := []string{"a.*", "exact", "*x"}
	for req, want := range map[string]bool{
		"a.b": true, "a.*": true, "exact": true, "exactly": false, "*": false, "b": false,
	} {
		if got := topicAllowed(req, allow); got != want {
			t.Errorf("topicAllowed(%q) = %v, want %v", req, got, want)
		}
	}
	if !topicAllowed("*", []string{"*"}) {
		t.Error(`"*" must be allowed when "*" is declared`)
	}
}

func TestStoreServerRoundTripAndErrors(t *testing.T) {
	ctx := context.Background()
	ok := &storeServer{s: &Services{Store: NewMemStore()}, module: "m"}
	if _, err := ok.Put(ctx, &agentv1.StorePutRequest{Key: "k1", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if _, err := ok.Put(
		ctx,
		&agentv1.StorePutRequest{Key: "other", Value: []byte("w")},
	); err != nil {
		t.Fatal(err)
	}
	got, err := ok.Get(ctx, &agentv1.StoreGetRequest{Key: "k1"})
	if err != nil || !got.GetFound() || string(got.GetValue()) != "v" {
		t.Fatalf("Get = %v, %v", got, err)
	}
	list, err := ok.List(ctx, &agentv1.StoreListRequest{Prefix: "k"})
	if err != nil || !slices.Equal(list.GetKeys(), []string{"k1"}) {
		t.Fatalf("List = %v, %v", list.GetKeys(), err)
	}
	if _, err := ok.Delete(ctx, &agentv1.StoreDeleteRequest{Key: "k1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := ok.Get(ctx, &agentv1.StoreGetRequest{Key: "k1"}); got.GetFound() {
		t.Fatal("key survived Delete")
	}

	bad := &storeServer{s: &Services{Store: errStore{}}, module: "m"}
	if _, err := bad.Get(ctx, &agentv1.StoreGetRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("Get err code = %v", status.Code(err))
	}
	if _, err := bad.Put(ctx, &agentv1.StorePutRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("Put err code = %v", status.Code(err))
	}
	if _, err := bad.Delete(
		ctx,
		&agentv1.StoreDeleteRequest{},
	); status.Code(
		err,
	) != codes.PermissionDenied {
		t.Errorf("Delete err code = %v", status.Code(err))
	}
	if _, err := bad.List(
		ctx,
		&agentv1.StoreListRequest{},
	); status.Code(
		err,
	) != codes.FailedPrecondition {
		t.Errorf("List err code = %v", status.Code(err))
	}
}

func TestPolicyServerGet(t *testing.T) {
	mp := NewMemPolicy()
	mp.Set("m", []byte("doc"))
	v := &policyServer{s: &Services{Policy: mp}, module: "m"}
	doc, err := v.Get(context.Background(), &agentv1.PolicyGetRequest{})
	if err != nil || doc.GetRevision() != 1 || string(doc.GetData()) != "doc" {
		t.Fatalf("Get = %v, %v", doc, err)
	}
	bad := &policyServer{
		s:      &Services{Policy: &scriptedPolicy{getErr: werror.ErrUnavailable}},
		module: "m",
	}
	if _, err := bad.Get(
		context.Background(),
		&agentv1.PolicyGetRequest{},
	); status.Code(
		err,
	) != codes.Unavailable {
		t.Fatalf("Get err code = %v", status.Code(err))
	}
}

// Watch sends on content change, not on every wake: an unchanged document
// after a wake is not re-sent, a changed one is.
func TestPolicyWatchSendsOnlyOnContentChange(t *testing.T) {
	changes := make(chan struct{}, 3)
	p := &scriptedPolicy{docs: [][]byte{[]byte("a"), []byte("a"), []byte("b")}, changes: changes}
	changes <- struct{}{}
	changes <- struct{}{}
	close(changes)

	st := &sendStream[agentv1.PolicyDocument]{ctx: context.Background()}
	v := &policyServer{s: &Services{Policy: p}, module: "m"}
	if err := v.Watch(&agentv1.PolicyWatchRequest{}, st); err != nil {
		t.Fatal(err)
	}
	if st.count() != 2 || string(st.sent[0].GetData()) != "a" ||
		string(st.sent[1].GetData()) != "b" {
		t.Fatalf("sent %v, want [a b]", st.sent)
	}
}

func TestPolicyWatchEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &scriptedPolicy{docs: [][]byte{[]byte("a")}, changes: make(chan struct{})}
	st := &sendStream[agentv1.PolicyDocument]{ctx: ctx, onSend: func(int) { cancel() }}
	v := &policyServer{s: &Services{Policy: p}, module: "m"}
	if err := v.Watch(&agentv1.PolicyWatchRequest{}, st); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyWatchErrors(t *testing.T) {
	v := &policyServer{s: &Services{Policy: &scriptedPolicy{getErr: werror.ErrDenied}}, module: "m"}
	st := &sendStream[agentv1.PolicyDocument]{ctx: context.Background()}
	if err := v.Watch(
		&agentv1.PolicyWatchRequest{},
		st,
	); status.Code(
		err,
	) != codes.PermissionDenied {
		t.Errorf("Get failure: code = %v", status.Code(err))
	}

	v = &policyServer{s: &Services{Policy: &scriptedPolicy{docs: [][]byte{nil}}}, module: "m"}
	st = &sendStream[agentv1.PolicyDocument]{ctx: context.Background(), sendErr: errBoom}
	if err := v.Watch(&agentv1.PolicyWatchRequest{}, st); !errors.Is(err, errBoom) {
		t.Errorf("send failure: %v", err)
	}
}

func TestEventsPublishReachesSubscriber(t *testing.T) {
	bus := eventbus.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := &eventsServer{s: &Services{Bus: bus}, module: "sub", allow: []string{"pub.*"}}
	pub := &eventsServer{s: &Services{Bus: bus}, module: "pub"}

	st := &sendStream[agentv1.Event]{ctx: ctx, onSend: func(int) { cancel() }}
	done := make(chan error, 1)
	go func() { done <- sub.Subscribe(&agentv1.SubscribeRequest{Topics: []string{"pub.t.x"}}, st) }()

	// The subscription is registered asynchronously; keep publishing until
	// one lands rather than guessing how long registration takes.
	deadline := time.After(5 * time.Second)
	for st.count() == 0 {
		if _, err := pub.Publish(
			context.Background(),
			&agentv1.PublishRequest{Topic: "t.x", Data: []byte("d")},
		); err != nil {
			t.Fatal(err)
		}
		select {
		case <-deadline:
			t.Fatal("event never delivered")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("Subscribe returned %v after ctx end", err)
	}
	if ev := st.sent[0]; ev.GetTopic() != "pub.t.x" || string(ev.GetData()) != "d" {
		t.Fatalf("got event %v", ev)
	}
}

func TestEventsSubscribeSendFailure(t *testing.T) {
	bus := eventbus.New()
	sub := &eventsServer{s: &Services{Bus: bus}, module: "sub", allow: []string{"x.t"}}
	st := &sendStream[agentv1.Event]{ctx: context.Background(), sendErr: errBoom}
	done := make(chan error, 1)
	go func() { done <- sub.Subscribe(&agentv1.SubscribeRequest{Topics: []string{"x.t"}}, st) }()
	for {
		bus.Publish("x", "t", nil)
		select {
		case err := <-done:
			if !errors.Is(err, errBoom) {
				t.Fatalf("Subscribe = %v, want the send error", err)
			}
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestIdentityServer(t *testing.T) {
	v := &identityServer{s: &Services{Identity: fakeIdentity{}}, module: "m"}
	id, err := v.WhoAmI(context.Background(), &agentv1.WhoAmIRequest{})
	if err != nil || id.GetDeviceId() != "dev-1" || id.GetEphemeral() || id.GetTenant() != "acme" {
		t.Fatalf("WhoAmI = %v, %v", id, err)
	}
	cred, err := v.Credential(
		context.Background(),
		&agentv1.CredentialRequest{Scopes: []string{"s"}},
	)
	if err != nil || cred.GetToken() != "tok-m" || cred.GetExpiresAt() != 42 ||
		!slices.Equal(cred.GetGrantedScopes(), []string{"s"}) {
		t.Fatalf("Credential = %v, %v", cred, err)
	}
	bad := &identityServer{s: &Services{Identity: fakeIdentity{err: errBoom}}, module: "m"}
	if _, err := bad.Credential(
		context.Background(),
		&agentv1.CredentialRequest{},
	); status.Code(
		err,
	) != codes.Unimplemented {
		t.Fatalf("failed mint must read Unimplemented, got %v", status.Code(err))
	}
}

func TestTransportServerSend(t *testing.T) {
	ft := &fakeTransport{}
	v := &transportServer{s: &Services{Transport: ft}, module: "m"}
	resp, err := v.Send(context.Background(), &agentv1.TransportSendRequest{
		Message: &agentv1.TransportMessage{
			Peer: agentv1.Peer_PEER_HYPERVISOR,
			Kind: "k",
			Data: []byte("d"),
		},
		QueueOffline: true,
	})
	if err != nil || !resp.GetDelivered() {
		t.Fatalf("Send = %v, %v", resp, err)
	}
	if want := "m/PEER_HYPERVISOR/k/d/true"; ft.got[0] != want {
		t.Fatalf("backend saw %q, want %q", ft.got[0], want)
	}
	ft.sendErr = errBoom
	if _, err := v.Send(
		context.Background(),
		&agentv1.TransportSendRequest{},
	); status.Code(
		err,
	) != codes.Unavailable {
		t.Fatalf("failed send code = %v", status.Code(err))
	}
}

func TestTransportServerReceive(t *testing.T) {
	in := make(chan *agentv1.TransportMessage, 2)
	in <- &agentv1.TransportMessage{Kind: "one"}
	close(in)
	v := &transportServer{s: &Services{Transport: &fakeTransport{inbound: in}}, module: "m"}
	st := &sendStream[agentv1.TransportMessage]{ctx: context.Background()}
	if err := v.Receive(&agentv1.TransportReceiveRequest{}, st); err != nil {
		t.Fatal(err)
	}
	if st.count() != 1 || st.sent[0].GetKind() != "one" {
		t.Fatalf("forwarded %v", st.sent)
	}

	in = make(chan *agentv1.TransportMessage, 1)
	in <- &agentv1.TransportMessage{}
	v = &transportServer{s: &Services{Transport: &fakeTransport{inbound: in}}, module: "m"}
	st = &sendStream[agentv1.TransportMessage]{ctx: context.Background(), sendErr: errBoom}
	if err := v.Receive(&agentv1.TransportReceiveRequest{}, st); !errors.Is(err, errBoom) {
		t.Fatalf("send failure: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v = &transportServer{
		s:      &Services{Transport: &fakeTransport{inbound: make(chan *agentv1.TransportMessage)}},
		module: "m",
	}
	if err := v.Receive(
		&agentv1.TransportReceiveRequest{},
		&sendStream[agentv1.TransportMessage]{ctx: ctx},
	); err != nil {
		t.Fatalf("ctx end: %v", err)
	}
}

// capture is a slog handler that keeps records, so the test can see what a
// module's log line became inside core's pipeline.
type capture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.recs = append(c.recs, r)
	c.mu.Unlock()
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func TestLogWriteReemitsAttributedToModule(t *testing.T) {
	h := &capture{}
	v := &logServer{s: &Services{Log: slog.New(h)}, module: "m"}
	st := &recvStream[agentv1.LogRecord, agentv1.LogWriteResponse]{
		recs: []*agentv1.LogRecord{{
			Level: int32(slog.LevelWarn), Message: "hello", Attrs: map[string]string{"k": "v"},
		}},
		endErr: io.EOF,
	}
	if err := v.Write(st); err != nil {
		t.Fatal(err)
	}
	if st.closed == nil {
		t.Fatal("normal end of stream must SendAndClose")
	}
	if len(h.recs) != 1 {
		t.Fatalf("got %d records", len(h.recs))
	}
	r := h.recs[0]
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
	if r.Message != "hello" || r.Level != slog.LevelWarn || attrs["module"] != "m" ||
		attrs["k"] != "v" {
		t.Fatalf("record = %v %v %q attrs %v", r.Level, r.Message, r.Message, attrs)
	}

	broken := &recvStream[agentv1.LogRecord, agentv1.LogWriteResponse]{endErr: errBoom}
	if err := v.Write(broken); !errors.Is(err, errBoom) {
		t.Fatalf("broken stream: %v", err)
	}
}

func TestSlogArgsDropsATrailingKey(t *testing.T) {
	got := slogArgs([]any{"a", 1, "dangling"})
	if len(got) != 1 || got[0].Key != "a" {
		t.Fatalf("slogArgs = %v", got)
	}
}

func TestWatchdogNotify(t *testing.T) {
	var pinged []string
	v := &watchdogServer{
		s:      &Services{Watchdog: func(m string) { pinged = append(pinged, m) }},
		module: "m",
	}
	st := &recvStream[agentv1.WatchdogPing, agentv1.WatchdogSummary]{
		recs:   []*agentv1.WatchdogPing{{Sequence: 1}, {Sequence: 2}},
		endErr: io.EOF,
	}
	if err := v.Notify(st); err != nil {
		t.Fatal(err)
	}
	if st.closed.GetReceived() != 2 || len(pinged) != 2 {
		t.Fatalf("summary %v, pings %v", st.closed, pinged)
	}

	nilSeam := &watchdogServer{s: &Services{}, module: "m"}
	st = &recvStream[agentv1.WatchdogPing, agentv1.WatchdogSummary]{
		recs: []*agentv1.WatchdogPing{{Sequence: 7}}, endErr: errBoom,
	}
	if err := nilSeam.Notify(st); !errors.Is(err, errBoom) {
		t.Fatalf("broken stream: %v", err)
	}
}

func TestMemStore(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if _, ok, _ := m.Get(ctx, "a", "k"); ok {
		t.Fatal("empty store found a key")
	}
	m.Put(ctx, "a", "k1", []byte("1")) //nolint:errcheck
	m.Put(ctx, "a", "x", []byte("2"))  //nolint:errcheck
	m.Put(ctx, "b", "k2", []byte("3")) //nolint:errcheck
	if v, ok, _ := m.Get(ctx, "a", "k1"); !ok || string(v) != "1" {
		t.Fatalf("Get = %q, %v", v, ok)
	}
	if keys, _ := m.List(ctx, "a", "k"); !slices.Equal(keys, []string{"k1"}) {
		t.Fatalf("List = %v (namespaces must not leak)", keys)
	}
	m.Delete(ctx, "a", "k1") //nolint:errcheck
	if _, ok, _ := m.Get(ctx, "a", "k1"); ok {
		t.Fatal("Delete left the key")
	}
}

func TestMemPolicyWakesAndForgetsWatchers(t *testing.T) {
	m := NewMemPolicy()
	ctx, cancel := context.WithCancel(context.Background())
	other, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()
	w := m.Watch(ctx, "m")
	m.Watch(other, "m")
	m.Set("m", []byte("a"))
	m.Set("m", []byte("b")) // buffer already full: must not block
	select {
	case <-w:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher not woken")
	}
	if rev, data, _ := m.Get(context.Background(), "m"); rev != 2 || string(data) != "b" {
		t.Fatalf("Get = %d %q", rev, data)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.watchers["m"])
		m.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancelled watcher not removed; %d remain", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStubIdentity(t *testing.T) {
	s := NewStubIdentity()
	id, eph, tenant := s.WhoAmI(context.Background())
	if !strings.HasPrefix(id, "ephemeral-") || !eph || tenant != "" {
		t.Fatalf("WhoAmI = %q %v %q", id, eph, tenant)
	}
	tok, exp, scopes, err := s.Credential(context.Background(), "m", []string{"a"})
	if err != nil || !strings.HasPrefix(tok, "stub-m-") || exp <= time.Now().Unix() ||
		!slices.Equal(scopes, []string{"a"}) {
		t.Fatalf("Credential = %q %d %v %v", tok, exp, scopes, err)
	}
}

func TestLogTransport(t *testing.T) {
	lt := &LogTransport{Log: quietLog()}
	if delivered, err := lt.Send(
		context.Background(),
		"m",
		agentv1.Peer_PEER_HYPERVISOR,
		"k",
		nil,
		false,
	); delivered ||
		err != nil {
		t.Fatalf("Send = %v, %v; nothing left the machine", delivered, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := lt.Receive(ctx, "m")
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("LogTransport delivered a message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Receive channel not closed at ctx end")
	}
}

// Transport traffic is routed under the channel address; every other service
// keys on the module id.
func TestNewServerRoutesTransportUnderChannelAddress(t *testing.T) {
	s := testServices()
	ft := &fakeTransport{}
	s.Transport = ft
	srv := s.NewServer("weave-linux-exec", "weave.exec", "tok", nil)
	info := srv.GetServiceInfo()
	if _, ok := info["weave.agent.v1.TransportService"]; !ok {
		t.Fatalf("transport service not registered: %v", info)
	}
	_, conn := serveServer(t, srv)
	cli := agentv1.NewTransportServiceClient(conn)
	if _, err := cli.Send(
		withToken("tok"),
		&agentv1.TransportSendRequest{Message: &agentv1.TransportMessage{
			Peer: agentv1.Peer_PEER_HYPERVISOR, Kind: "k",
		}},
	); err != nil {
		t.Fatal(err)
	}
	if len(ft.got) != 1 || !strings.HasPrefix(ft.got[0], "weave.exec/") {
		t.Fatalf("sent as %v, want the channel address", ft.got)
	}
}

type disabledIdentity struct{ fakeIdentity }

func (disabledIdentity) Unavailable() error { return errors.New("store sealed elsewhere") }

// An identity core could not load is refused, not served as an empty one.
func TestIdentityServerUnavailable(t *testing.T) {
	v := &identityServer{s: &Services{Identity: disabledIdentity{}}, module: "m"}
	if _, err := v.WhoAmI(context.Background(), &agentv1.WhoAmIRequest{}); status.Code(err) != codes.Unavailable ||
		!strings.Contains(err.Error(), "sealed elsewhere") {
		t.Fatalf("WhoAmI = %v", err)
	}
}

type availableIdentity struct{ fakeIdentity }

func (availableIdentity) Unavailable() error { return nil }

func TestIdentityServerAvailable(t *testing.T) {
	v := &identityServer{s: &Services{Identity: availableIdentity{}}, module: "m"}
	if id, err := v.WhoAmI(context.Background(), &agentv1.WhoAmIRequest{}); err != nil || id.GetDeviceId() != "dev-1" {
		t.Fatalf("WhoAmI = %v, %v", id, err)
	}
}
