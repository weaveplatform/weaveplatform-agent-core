package hostserv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
)

// The in-memory backends carry the seams until the real implementations
// land: the encrypted store (M5), the policy pipeline (M5), enrolment
// (M7) and the transport mux (M7).

// MemStore is a process-lifetime store.
type MemStore struct {
	mu   sync.Mutex
	data map[string]map[string][]byte
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{data: make(map[string]map[string][]byte)}
}

// Get implements StoreBackend.
func (m *MemStore) Get(_ context.Context, module, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[module][key]
	return v, ok, nil
}

// Put implements StoreBackend.
func (m *MemStore) Put(_ context.Context, module, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[module] == nil {
		m.data[module] = make(map[string][]byte)
	}
	m.data[module][key] = value
	return nil
}

// Delete implements StoreBackend.
func (m *MemStore) Delete(_ context.Context, module, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data[module], key)
	return nil
}

// List implements StoreBackend.
func (m *MemStore) List(_ context.Context, module, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data[module] {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// MemPolicy delivers per-module documents set by core (or tests).
type MemPolicy struct {
	mu       sync.Mutex
	docs     map[string]memPolicyDoc
	watchers map[string][]chan struct{}
}

type memPolicyDoc struct {
	revision uint64
	data     []byte
}

// NewMemPolicy returns an empty policy backend.
func NewMemPolicy() *MemPolicy {
	return &MemPolicy{
		docs:     make(map[string]memPolicyDoc),
		watchers: make(map[string][]chan struct{}),
	}
}

// Set replaces a module's document and wakes its watchers.
func (m *MemPolicy) Set(module string, data []byte) {
	m.mu.Lock()
	doc := m.docs[module]
	doc.revision++
	doc.data = data
	m.docs[module] = doc
	watchers := append([]chan struct{}(nil), m.watchers[module]...)
	m.mu.Unlock()
	for _, w := range watchers {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

// Get implements PolicyBackend.
func (m *MemPolicy) Get(_ context.Context, module string) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc := m.docs[module]
	return doc.revision, doc.data, nil
}

// Watch implements PolicyBackend.
func (m *MemPolicy) Watch(ctx context.Context, module string) <-chan struct{} {
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	m.watchers[module] = append(m.watchers[module], ch)
	m.mu.Unlock()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		ws := m.watchers[module]
		for i, w := range ws {
			if w == ch {
				m.watchers[module] = append(ws[:i], ws[i+1:]...)
				break
			}
		}
		m.mu.Unlock()
	}()
	return ch
}

// StubIdentity is an in-memory identity for tests and tools that run host
// services without core's identity provider: an ephemeral device id minted
// when it is made.
type StubIdentity struct {
	DeviceID string
}

// NewStubIdentity mints a random ephemeral identity.
func NewStubIdentity() *StubIdentity {
	var b [8]byte
	rand.Read(b[:])
	return &StubIdentity{DeviceID: "ephemeral-" + hex.EncodeToString(b[:])}
}

// WhoAmI implements IdentityBackend.
func (s *StubIdentity) WhoAmI(_ context.Context) (string, bool, string) {
	return s.DeviceID, true, ""
}

// Credential implements IdentityBackend.
func (s *StubIdentity) Credential(
	_ context.Context, module string, scopes []string,
) (string, int64, []string, error) {
	var b [16]byte
	rand.Read(b[:])
	return "stub-" + module + "-" + hex.EncodeToString(b[:]),
		time.Now().Add(time.Hour).Unix(), scopes, nil
}

// LogTransport logs sends and delivers nothing inbound: a stand-in for tests
// that need a transport but no host. Sends report delivered=false so honest
// modules know nothing left the machine.
type LogTransport struct {
	Log *slog.Logger
}

// Send implements TransportBackend.
func (t *LogTransport) Send(
	_ context.Context,
	module string,
	peer agentv1.Peer,
	kind string,
	data []byte,
	queueOffline bool,
) (bool, error) {
	t.Log.Info(
		"transport send (no peer connected)",
		"module",
		module,
		"peer",
		peer.String(),
		"kind",
		kind,
		"bytes",
		len(data),
		"queue_offline",
		queueOffline,
	)
	return false, nil
}

// Receive implements TransportBackend.
func (t *LogTransport) Receive(
	ctx context.Context,
	module string,
) <-chan *agentv1.TransportMessage {
	ch := make(chan *agentv1.TransportMessage)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}
