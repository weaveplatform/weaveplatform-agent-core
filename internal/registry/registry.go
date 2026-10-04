// Package registry is core's one table of installed modules: what each is,
// where it answers on the host channel, and what state it is in. The
// supervisor feeds it; everything that asks "is this module here, and can it
// take a message" reads it — transport delivery, the host channel's
// modules.list, the RegistryService host service and ControlService.Modules.
//
// One table, not one per view, because the views must not disagree: a host
// told by modules.list that a module is running must not then be told by
// delivery.failed that it is not installed.
package registry

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
)

// State is a module's lifecycle state, the vocabulary every view reports.
type State string

const (
	// StatePending: registered, not yet launched.
	StatePending State = "pending"
	// StateStarting: spawn through handshake through Start.
	StateStarting State = "starting"
	// StateRunning: started and passing health checks.
	StateRunning State = "running"
	// StateBackoff: crashed; waiting out the restart delay.
	StateBackoff State = "backoff"
	// StateStartLimited: hit the start-limit (too many restarts in the
	// window); not restarting. Fail closed: an operator (or a rollback)
	// resets it. This is systemd's StartLimit, not a Fowler circuit breaker
	// (there is no half-open probe; it gates restarts, not calls).
	StateStartLimited State = "start-limited"
	// StateUnsupportedProtocol: the module refused the advertised window
	// (exit 78). Restarting cannot help; not a crash loop.
	StateUnsupportedProtocol State = "unsupported-protocol"
	// StateRequirementsUnmet: the manifest requires capabilities this
	// host lacks, or a placement core refuses. Never launched.
	StateRequirementsUnmet State = "requirements-unmet"
	// StateWaitingForSession: a per-user-console module with nobody at the
	// console. Not a failure: it starts when a user logs in.
	StateWaitingForSession State = "waiting-for-session"
	// StateStopped: cleanly stopped (core shutdown or operator).
	StateStopped State = "stopped"
)

// Module is one installed module's entry.
type Module struct {
	ID       string
	Version  string
	Protocol uint32
	// Address is the name the module answers to on the host channel: the
	// manifest address, or the id.
	Address      string
	Capabilities []string
	Privilege    string
	Session      string

	State State
	// Detail explains non-running states (missing caps, start-limit cause).
	Detail   string
	PID      int
	Restarts uint32
	// Health is the last poll result; nil when never polled.
	Health   *agentv1.Health
	Since    time.Time
	Surfaces []*agentv1.Surface
}

// Registry is safe for concurrent use. The zero value is ready.
type Registry struct {
	mu       sync.Mutex
	modules  map[string]Module
	revision uint64
	watchers map[chan struct{}]struct{}
}

// New returns an empty registry.
func New() *Registry { return &Registry{} }

// Set records m, replacing any entry with the same id. Watchers are woken
// only when something a reader would act on changed: the supervisor re-records
// a module on every health poll, and waking every host and module every 30s
// per module to say nothing happened would bury the changes that matter.
func (r *Registry) Set(m Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.modules == nil {
		r.modules = make(map[string]Module)
	}
	old, had := r.modules[m.ID]
	r.modules[m.ID] = m
	if had && !changed(old, m) {
		return
	}
	r.bumpLocked()
}

// Remove drops the entry for id. No-op for unknown ids.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.modules[id]; !ok {
		return
	}
	delete(r.modules, id)
	r.bumpLocked()
}

func (r *Registry) bumpLocked() {
	r.revision++
	for ch := range r.watchers {
		// Coalescing: one pending signal is as good as many, because a
		// woken reader takes a whole snapshot rather than a delta.
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// changed reports whether b differs from a in anything but the health
// details map and the surfaces, which a module may refresh on every poll.
func changed(a, b Module) bool {
	return a.Version != b.Version || a.Protocol != b.Protocol || a.Address != b.Address ||
		a.Privilege != b.Privilege || a.Session != b.Session ||
		!slices.Equal(a.Capabilities, b.Capabilities) ||
		a.State != b.State || a.Detail != b.Detail || a.PID != b.PID ||
		a.Restarts != b.Restarts || !a.Since.Equal(b.Since) ||
		a.Health.GetStatus() != b.Health.GetStatus() ||
		a.Health.GetReason() != b.Health.GetReason()
}

// Get returns the entry for id.
func (r *Registry) Get(id string) (Module, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.modules[id]
	return m, ok
}

// ByAddress returns the module that answers to a host channel address. The
// supervisor refuses a second module on a taken address, so there is at most
// one.
func (r *Registry) ByAddress(address string) (Module, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.modules {
		if m.Address == address {
			return m, true
		}
	}
	return Module{}, false
}

// List returns every entry, sorted by id, and the revision it reflects. The
// revision increases on every change a watcher is woken for, so a reader that
// receives snapshots out of order keeps the one with the higher revision.
func (r *Registry) List() (uint64, []Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return r.revision, out
}

// Watch returns a channel that receives a signal after each change until ctx
// ends, when it is closed. Signals coalesce: a slow reader sees one, then
// reads List for the current state.
func (r *Registry) Watch(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	r.mu.Lock()
	if r.watchers == nil {
		r.watchers = make(map[chan struct{}]struct{})
	}
	r.watchers[ch] = struct{}{}
	r.mu.Unlock()
	context.AfterFunc(ctx, func() {
		r.mu.Lock()
		delete(r.watchers, ch)
		r.mu.Unlock()
		close(ch)
	})
	return ch
}
