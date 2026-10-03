package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
)

var errInjected = errors.New("injected")

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type flakyCache struct {
	*hostserv.MemStore
	getErr, putErr error
}

func (c flakyCache) Get(ctx context.Context, m, k string) ([]byte, bool, error) {
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	return c.MemStore.Get(ctx, m, k)
}

func (c flakyCache) Put(ctx context.Context, m, k string, v []byte) error {
	if c.putErr != nil {
		return c.putErr
	}
	return c.MemStore.Put(ctx, m, k, v)
}

func TestLoadToleratesAMissingOrBrokenCache(t *testing.T) {
	(&Manager{Log: quiet()}).Load(t.Context()) // no cache configured

	for name, cache := range map[string]hostserv.StoreBackend{
		"unreadable": flakyCache{MemStore: hostserv.NewMemStore(), getErr: errInjected},
		"empty":      hostserv.NewMemStore(),
	} {
		m := &Manager{Log: quiet(), Cache: cache}
		m.Load(t.Context())
		if rev, _, _ := m.Get(context.Background(), "x"); rev != 0 {
			t.Errorf("%s: revision %d from nothing", name, rev)
		}
	}

	corrupt := hostserv.NewMemStore()
	corrupt.Put(context.Background(), cacheNamespace, "document", []byte("{")) //nolint:errcheck
	m := &Manager{Log: quiet(), Cache: corrupt}
	m.Load(t.Context())
	if rev, _, _ := m.Get(context.Background(), "x"); rev != 0 {
		t.Errorf("corrupt cache produced revision %d", rev)
	}
}

// A failed cache write costs restarts their last-known policy, but must not
// stop the document being delivered now.
func TestApplyDeliversDespiteACacheFailure(t *testing.T) {
	m := &Manager{
		Log:   quiet(),
		Cache: flakyCache{MemStore: hostserv.NewMemStore(), putErr: errInjected},
	}
	m.apply(
		t.Context(),
		Document{Revision: 1, Modules: map[string]json.RawMessage{"a": json.RawMessage(`1`)}},
		true,
	)
	if _, doc, _ := m.Get(context.Background(), "a"); string(doc) != "1" {
		t.Fatalf("doc = %q", doc)
	}
}

// A module dropped from the policy set loses its document, and its watcher
// is told — otherwise it would run on revoked policy indefinitely.
func TestApplyRemovesDroppedModulesAndWakesThem(t *testing.T) {
	m := &Manager{Log: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := m.Watch(ctx, "gone")
	m.apply(
		t.Context(),
		Document{Revision: 1, Modules: map[string]json.RawMessage{"gone": json.RawMessage(`1`)}},
		false,
	)
	<-w
	m.apply(t.Context(), Document{Revision: 2, Modules: map[string]json.RawMessage{}}, false)
	select {
	case <-w:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher of a dropped module not woken")
	}
	if _, doc, _ := m.Get(context.Background(), "gone"); doc != nil {
		t.Fatalf("dropped module still has %q", doc)
	}

	// A second wake while the first is unread must not block apply.
	m.apply(
		t.Context(),
		Document{Revision: 3, Modules: map[string]json.RawMessage{"gone": json.RawMessage(`2`)}},
		false,
	)
	m.apply(
		t.Context(),
		Document{Revision: 4, Modules: map[string]json.RawMessage{"gone": json.RawMessage(`3`)}},
		false,
	)
}

func TestWatchForgetsCancelledWatchers(t *testing.T) {
	m := &Manager{Log: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	keep, cancelKeep := context.WithCancel(context.Background())
	defer cancelKeep()
	m.Watch(keep, "a")
	m.Watch(ctx, "a")
	cancel()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.watchers["a"]) == 1
	})
}
