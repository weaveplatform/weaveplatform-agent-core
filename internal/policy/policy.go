// Package policy loads, caches and delivers module policy. The policy set is
// a local file — written by whoever administers the machine, or by the host
// that drives it — which core re-reads when it changes. The last good
// document is cached in the store, so a file that is malformed at start still
// leaves the device on its last-known policy. Each module's Watch stream is
// woken when its document changes.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
)

// cacheNamespace is the store namespace policy documents cache under. It
// is core-owned; no module id collides because module ids never contain
// a dot.
const cacheNamespace = "core.policy"

// DefaultInterval is how often the policy file is checked for a change. A
// stat is cheap; the bound is how stale a module's policy may be after the
// file is replaced.
const DefaultInterval = 30 * time.Second

// maxFileSize bounds the policy file read; a larger file is treated as
// malformed rather than read into memory.
const maxFileSize = 8 << 20

// Document is the policy set: one opaque payload per module.
type Document struct {
	Revision uint64                     `json:"revision"`
	Modules  map[string]json.RawMessage `json:"modules"`
}

// Manager implements hostserv.PolicyBackend and owns the file watch.
type Manager struct {
	Log *slog.Logger
	// Path is the policy file. Empty disables the file: the manager serves
	// only cached/injected documents.
	Path string
	// Interval between checks of the file; zero gets DefaultInterval.
	Interval time.Duration
	// Cache persists the last good document across restarts; nil disables.
	Cache hostserv.StoreBackend

	mu       sync.Mutex
	revision uint64
	docs     map[string][]byte
	watchers map[string][]chan struct{}

	// stamp is the file state last acted on; only Load and Run touch it,
	// and Run starts after Load returns.
	stamp   fileStamp
	stamped bool
}

// fileStamp identifies a version of the policy file without reading it.
// Size is in it because a rewrite within the filesystem's mtime granularity
// otherwise looks unchanged.
type fileStamp struct {
	exists bool
	mod    time.Time
	size   int64
}

// Load primes the manager from the cache, then from the file. Call once
// before modules start, so the first Get already reflects the file, and
// before Run.
func (m *Manager) Load(ctx context.Context) {
	m.loadCache(ctx)
	m.check(ctx)
}

func (m *Manager) loadCache(ctx context.Context) {
	if m.Cache == nil {
		return
	}
	raw, found, err := m.Cache.Get(ctx, cacheNamespace, "document")
	if err != nil || !found {
		return
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		m.Log.Warn("discarding corrupt policy cache", "err", err)
		return
	}
	m.apply(ctx, doc, false)
	m.Log.Info("policy loaded from cache", "revision", doc.Revision)
}

// Run re-checks the file until ctx ends. Returns at once when Path is empty.
func (m *Manager) Run(ctx context.Context) {
	if m.Path == "" {
		return
	}
	interval := m.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.check(ctx)
		}
	}
}

// check reads the file if it changed since the last check.
//
// A missing file is no policy: every module's document is withdrawn, as if
// an empty set had been delivered. A malformed file is logged and otherwise
// ignored — the last good policy (possibly from the cache) stays in force,
// because failing open to "no policy" would let a half-written or mistyped
// file revoke every module's policy at once. A file that cannot be stat'd or
// read for another reason (permissions) is retried on the next check.
func (m *Manager) check(ctx context.Context) {
	if m.Path == "" {
		return
	}
	st, err := m.stat()
	if err != nil {
		m.Log.Warn("policy file unreadable", "path", m.Path, "err", err)
		return
	}
	if m.stamped && st == m.stamp {
		return
	}
	if !st.exists {
		m.stamp, m.stamped = st, true
		m.apply(ctx, Document{}, true)
		return
	}
	doc, err := m.read()
	if err != nil {
		if errors.Is(err, errMalformed) {
			// Remember it: logging the same broken file every interval
			// would bury the next real change in the log.
			m.stamp, m.stamped = st, true
		}
		m.Log.Error("policy file not applied; keeping the last good policy",
			"path", m.Path, "err", err)
		return
	}
	m.stamp, m.stamped = st, true
	m.apply(ctx, doc, true)
}

var errMalformed = errors.New("malformed policy document")

func (m *Manager) stat() (fileStamp, error) {
	fi, err := os.Stat(m.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileStamp{}, nil
	}
	if err != nil {
		return fileStamp{}, fmt.Errorf("stat: %w", err)
	}
	return fileStamp{exists: true, mod: fi.ModTime(), size: fi.Size()}, nil
}

func (m *Manager) read() (Document, error) {
	f, err := os.Open(m.Path)
	if err != nil {
		return Document{}, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Document{}, fmt.Errorf("read: %w", err)
	}
	if len(body) > maxFileSize {
		return Document{}, fmt.Errorf("%w: larger than %d bytes", errMalformed, maxFileSize)
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return Document{}, fmt.Errorf("%w: %w", errMalformed, err)
	}
	return doc, nil
}

// apply installs a document, wakes watchers of changed modules, and
// (optionally) caches it.
//
// Change is decided by per-module content, not by revision: a file edited
// without bumping its revision must still take effect, and one restored from
// a backup can carry a lower revision. A rule of "refuse revision <= current"
// would ignore both — and the stale revision would survive restarts through
// the cache.
func (m *Manager) apply(ctx context.Context, doc Document, cache bool) {
	m.mu.Lock()
	if doc.Revision < m.revision {
		m.Log.Warn("policy revision went backwards; applying it anyway",
			"from", m.revision, "to", doc.Revision)
	}
	revChanged := doc.Revision != m.revision
	m.revision = doc.Revision
	if m.docs == nil {
		m.docs = make(map[string][]byte)
	}
	var changed []string
	seen := make(map[string]bool)
	for id, raw := range doc.Modules {
		seen[id] = true
		if string(m.docs[id]) != string(raw) {
			m.docs[id] = []byte(raw)
			changed = append(changed, id)
		}
	}
	for id := range m.docs {
		if !seen[id] {
			delete(m.docs, id)
			changed = append(changed, id)
		}
	}
	var wake []chan struct{}
	for _, id := range changed {
		wake = append(wake, m.watchers[id]...)
	}
	m.mu.Unlock()
	if !revChanged && len(changed) == 0 {
		return
	}

	for _, w := range wake {
		select {
		case w <- struct{}{}:
		default:
		}
	}
	if cache && m.Cache != nil {
		if raw, err := json.Marshal(doc); err == nil {
			// Without cancel: a document already applied is cached even
			// when the check that applied it is being shut down.
			if err := m.Cache.Put(
				context.WithoutCancel(ctx),
				cacheNamespace,
				"document",
				raw,
			); err != nil {
				m.Log.Warn("caching policy failed", "err", err)
			}
		}
	}
	if len(changed) > 0 {
		m.Log.Info("policy applied", "revision", doc.Revision, "changed", changed)
	}
}

// Get implements hostserv.PolicyBackend. It serves the in-memory snapshot,
// so ctx is accepted for interface parity and cancellation but never blocks.
func (m *Manager) Get(_ context.Context, module string) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revision, m.docs[module], nil
}

// Watch implements hostserv.PolicyBackend.
func (m *Manager) Watch(ctx context.Context, module string) <-chan struct{} {
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	if m.watchers == nil {
		m.watchers = make(map[string][]chan struct{})
	}
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
