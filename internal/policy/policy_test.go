package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

func writePolicy(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func policyFor(rev, interval int) string {
	b, _ := json.Marshal(map[string]any{
		"revision": rev,
		"modules": map[string]any{
			"weave-linux-presence": map[string]int{"interval_seconds": interval},
		},
	})
	return string(b)
}

func TestFileLoadWatchAndCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, policyFor(1, 60))

	st, err := store.Open(dir, keyprotect.New())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := &Manager{Log: log, Path: path, Interval: 20 * time.Millisecond, Cache: st}
	m.Load(t.Context())
	// Load reads the file synchronously: modules starting right after it
	// see the file's policy, not whatever the cache held.
	if _, doc, _ := m.Get(context.Background(), "weave-linux-presence"); intervalOf(t, doc) != 60 {
		t.Fatalf("after Load: %s", doc)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	// A replaced file reaches a watcher, even without a revision bump.
	watch := m.Watch(ctx, "weave-linux-presence")
	writePolicy(t, path, policyFor(1, 5))
	select {
	case <-watch:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher never woke on policy change")
	}
	rev, doc, _ := m.Get(context.Background(), "weave-linux-presence")
	if got := intervalOf(t, doc); got != 5 || rev != 1 {
		t.Fatalf("interval = %d, doc = %s (rev %d)", got, doc, rev)
	}

	cancel()
	<-done
	st.Close()

	// A fresh manager with no file serves the cached document.
	st2, err := store.Open(dir, keyprotect.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	m2 := &Manager{Log: log, Cache: st2}
	m2.Load(t.Context())
	_, doc2, _ := m2.Get(context.Background(), "weave-linux-presence")
	if intervalOf(t, doc2) != 5 {
		t.Fatalf("cache miss after restart: %s", doc2)
	}
}

// syncBuf is a log sink safe for the manager to write while the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

// A malformed file keeps the last good policy (here, from the cache) and is
// reported once, not on every check; fixing it applies the new policy.
func TestMalformedFileKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	cache := hostserv.NewMemStore()
	raw, _ := json.Marshal(
		Document{
			Revision: 3,
			Modules: map[string]json.RawMessage{
				"weave-linux-presence": json.RawMessage(`{"interval_seconds":60}`),
			},
		},
	)
	cache.Put(context.Background(), cacheNamespace, "document", raw) //nolint:errcheck

	logs := &syncBuf{}
	m := &Manager{Log: slog.New(slog.NewTextHandler(logs, nil)), Path: path, Cache: cache}
	writePolicy(t, path, "{not json")
	m.Load(t.Context())
	m.check(t.Context())
	if rev, doc, _ := m.Get(
		context.Background(),
		"weave-linux-presence",
	); rev != 3 ||
		intervalOf(t, doc) != 60 {
		t.Fatalf("malformed file displaced the last good policy: rev %d %s", rev, doc)
	}
	if n := logs.count("policy file not applied"); n != 1 {
		t.Fatalf("malformed file reported %d times, want once", n)
	}

	writePolicy(t, path, policyFor(4, 7))
	m.check(t.Context())
	if rev, doc, _ := m.Get(
		context.Background(),
		"weave-linux-presence",
	); rev != 4 ||
		intervalOf(t, doc) != 7 {
		t.Fatalf("fixed file not applied: rev %d %s", rev, doc)
	}

	// Oversized counts as malformed too.
	writePolicy(t, path, `{"revision":5,"pad":"`+strings.Repeat("x", maxFileSize)+`"}`)
	m.check(t.Context())
	if rev, _, _ := m.Get(context.Background(), "weave-linux-presence"); rev != 4 {
		t.Fatalf("oversized file applied: rev %d", rev)
	}
	if n := logs.count("larger than"); n != 1 {
		t.Fatalf("oversized file reported %d times", n)
	}
}

// A missing file is no policy: documents loaded from the cache are
// withdrawn and their watchers woken. The file appearing later applies.
func TestMissingFileIsNoPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	cache := hostserv.NewMemStore()
	raw, _ := json.Marshal(
		Document{
			Revision: 3,
			Modules: map[string]json.RawMessage{
				"weave-linux-presence": json.RawMessage(`{"interval_seconds":60}`),
			},
		},
	)
	cache.Put(context.Background(), cacheNamespace, "document", raw) //nolint:errcheck

	m := &Manager{Log: quiet(), Path: path, Cache: cache}
	m.loadCache(t.Context())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := m.Watch(ctx, "weave-linux-presence")
	m.check(t.Context())
	select {
	case <-w:
	default:
		t.Fatal("watcher not told its policy was withdrawn")
	}
	if rev, doc, _ := m.Get(context.Background(), "weave-linux-presence"); rev != 0 || doc != nil {
		t.Fatalf("missing file left rev %d %s", rev, doc)
	}
	// The withdrawal is what a restart now starts from.
	if raw, _, _ := cache.Get(
		context.Background(),
		cacheNamespace,
		"document",
	); strings.Contains(
		string(raw),
		"weave-linux-presence",
	) {
		t.Fatalf("cache still holds the withdrawn policy: %s", raw)
	}

	m.check(t.Context()) // still missing: nothing to do
	writePolicy(t, path, policyFor(1, 9))
	m.check(t.Context())
	if _, doc, _ := m.Get(context.Background(), "weave-linux-presence"); intervalOf(t, doc) != 9 {
		t.Fatalf("new file not applied: %s", doc)
	}
}

// A file that cannot be stat'd or read is retried, not remembered: the fix
// (a chmod, say) need not change the file's mtime.
func TestUnreadableFileIsRetried(t *testing.T) {
	m := &Manager{Log: quiet(), Path: "bad\x00path"}
	m.check(t.Context())
	if m.stamped {
		t.Fatal("a failed stat was remembered")
	}

	if runtime.GOOS == "windows" {
		return // reading a directory handle is not a portable failure
	}
	dir := t.TempDir()
	m = &Manager{Log: quiet(), Path: dir} // a directory: stats, cannot be read as a file
	m.check(t.Context())
	if m.stamped {
		t.Fatal("a failed read was remembered")
	}
	if rev, _, _ := m.Get(context.Background(), "x"); rev != 0 {
		t.Fatal("an unreadable file produced a policy")
	}
}

func TestNoPathServesOnlyTheCache(t *testing.T) {
	m := &Manager{Log: quiet()}
	m.Load(t.Context())
	done := make(chan struct{})
	go func() { m.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run with no path kept running")
	}
}

func TestRunDefaultsTheInterval(t *testing.T) {
	m := &Manager{Log: quiet(), Path: filepath.Join(t.TempDir(), "policy.json")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

// TestRevisionRegressionAccepted proves a policy whose revision goes
// backwards (a file restored from a backup) still delivers, rather than
// bricking policy delivery as a "refuse revision <= current" rule would.
func TestRevisionRegressionAccepted(t *testing.T) {
	m := &Manager{Log: quiet()}

	m.apply(t.Context(), Document{Revision: 10, Modules: map[string]json.RawMessage{
		"weave-linux-presence": json.RawMessage(`{"interval_seconds":60}`),
	}}, false)
	if _, doc, _ := m.Get(context.Background(), "weave-linux-presence"); intervalOf(t, doc) != 60 {
		t.Fatalf("first apply not stored")
	}

	m.apply(t.Context(), Document{Revision: 1, Modules: map[string]json.RawMessage{
		"weave-linux-presence": json.RawMessage(`{"interval_seconds":5}`),
	}}, false)
	if _, doc, _ := m.Get(context.Background(), "weave-linux-presence"); intervalOf(t, doc) != 5 {
		t.Fatalf("revision regression ignored: policy delivery bricked")
	}

	// Same revision, same content: no-op (no spurious change).
	m.apply(t.Context(), Document{Revision: 1, Modules: map[string]json.RawMessage{
		"weave-linux-presence": json.RawMessage(`{"interval_seconds":5}`),
	}}, false)
	if _, doc, _ := m.Get(context.Background(), "weave-linux-presence"); intervalOf(t, doc) != 5 {
		t.Fatalf("idempotent re-apply changed the doc")
	}
}

func intervalOf(t *testing.T, doc []byte) int {
	t.Helper()
	var p struct {
		IntervalSeconds int `json:"interval_seconds"`
	}
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatalf("unmarshal %q: %v", doc, err)
	}
	return p.IntervalSeconds
}

func waitFor(t *testing.T, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}
