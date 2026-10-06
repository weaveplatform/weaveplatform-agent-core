package registry

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
)

func signalled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

func TestLookups(t *testing.T) {
	var r Registry // the zero value is ready
	if _, ok := r.Get("a"); ok {
		t.Fatal("empty registry found a module")
	}
	r.Set(Module{ID: "b", Address: "weave.b", State: StateRunning})
	r.Set(Module{ID: "a", Address: "a", State: StatePending})

	if m, ok := r.Get("b"); !ok || m.Address != "weave.b" {
		t.Fatalf("Get(b) = %+v %v", m, ok)
	}
	if m, ok := r.ByAddress("weave.b"); !ok || m.ID != "b" {
		t.Fatalf("ByAddress = %+v %v", m, ok)
	}
	if _, ok := r.ByAddress("nowhere"); ok {
		t.Fatal("ByAddress found an address nobody answers to")
	}
	r.Set(Module{ID: "c", State: StateInvalid, Detail: "no binary"})
	if m, ok := r.ByAddress(""); ok {
		t.Fatalf("an empty address found %+v", m)
	}
	r.Remove("c")
	rev, mods := r.List()
	if rev != 4 || len(mods) != 2 || mods[0].ID != "a" || mods[1].ID != "b" {
		t.Fatalf("List = %d %+v", rev, mods)
	}
}

func TestStateTransitionsNotify(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.Watch(ctx)

	m := Module{ID: "m", Address: "m", State: StatePending}
	r.Set(m)
	if !signalled(ch) {
		t.Fatal("adding a module did not notify")
	}
	for _, st := range []State{StateStarting, StateRunning, StateBackoff, StateStartLimited} {
		m.State = st
		r.Set(m)
		if !signalled(ch) {
			t.Fatalf("moving to %s did not notify", st)
		}
		if got, _ := r.Get("m"); got.State != st {
			t.Fatalf("state = %s, want %s", got.State, st)
		}
	}

	// A re-record with nothing a reader acts on stays quiet: health details
	// and surfaces change on every poll.
	m.Health = &agentv1.Health{
		Status:  agentv1.Health_STATUS_HEALTHY,
		Details: map[string]string{"n": "1"},
	}
	r.Set(m)
	if !signalled(ch) {
		t.Fatal("a health status change did not notify")
	}
	rev, _ := r.List()
	m.Health = &agentv1.Health{
		Status:  agentv1.Health_STATUS_HEALTHY,
		Details: map[string]string{"n": "2"},
	}
	m.Surfaces = []*agentv1.Surface{{}}
	r.Set(m)
	if signalled(ch) {
		t.Fatal("an unchanged module notified")
	}
	if now, _ := r.List(); now != rev {
		t.Fatalf("revision moved without a change: %d -> %d", rev, now)
	}
	if got, _ := r.Get("m"); got.Health.GetDetails()["n"] != "2" {
		t.Fatal("the quiet re-record was not stored")
	}

	m.Health = &agentv1.Health{Status: agentv1.Health_STATUS_HEALTHY, Reason: "now with a reason"}
	r.Set(m)
	if !signalled(ch) {
		t.Fatal("a health reason change did not notify")
	}

	r.Remove("m")
	if !signalled(ch) {
		t.Fatal("removal did not notify")
	}
	r.Remove("m")
	if signalled(ch) {
		t.Fatal("removing an unknown id notified")
	}

	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("a stale signal was left after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("the watch channel was not closed when its context ended")
	}
}

// Signals coalesce: a reader that falls behind sees one, not a backlog.
func TestWatchCoalesces(t *testing.T) {
	r := New()
	ch := r.Watch(t.Context())
	for i := range 10 {
		r.Set(Module{ID: "m", Restarts: uint32(i)})
	}
	if !signalled(ch) {
		t.Fatal("no signal")
	}
	if signalled(ch) {
		t.Fatal("signals did not coalesce")
	}
	if rev, _ := r.List(); rev != 10 {
		t.Fatalf("revision = %d, want 10", rev)
	}
}

func TestChangedFields(t *testing.T) {
	base := Module{ID: "m", Capabilities: []string{"a"}}
	for name, mut := range map[string]func(*Module){
		"version":      func(m *Module) { m.Version = "2" },
		"protocol":     func(m *Module) { m.Protocol = 2 },
		"address":      func(m *Module) { m.Address = "x" },
		"privilege":    func(m *Module) { m.Privilege = "user" },
		"session":      func(m *Module) { m.Session = "per-user-console" },
		"capabilities": func(m *Module) { m.Capabilities = []string{"b"} },
		"detail":       func(m *Module) { m.Detail = "why" },
		"pid":          func(m *Module) { m.PID = 7 },
		"since":        func(m *Module) { m.Since = time.Unix(1, 0) },
	} {
		next := base
		mut(&next)
		if !changed(base, next) {
			t.Errorf("a %s change was not noticed", name)
		}
	}
}

// Core's own condition is reported beside the modules, wakes watchers when it
// changes and only then, and is handed out as a copy.
func TestCoreCondition(t *testing.T) {
	r := New()
	if c := r.Core(); c.Degraded != "" || c.Unavailable != nil {
		t.Fatalf("a new registry is degraded: %+v", c)
	}
	ch := r.Watch(t.Context())
	rev, _ := r.List()
	unavailable := []string{"store", "identity"}
	r.SetCore(Core{Degraded: "store sealed elsewhere", Unavailable: unavailable})
	if !signalled(ch) {
		t.Fatal("a change of condition did not wake the watcher")
	}
	if next, _ := r.List(); next <= rev {
		t.Fatalf("revision %d did not move past %d", next, rev)
	}
	unavailable[0] = "mutated"
	c := r.Core()
	if c.Degraded != "store sealed elsewhere" || c.Unavailable[0] != "store" {
		t.Fatalf("Core = %+v", c)
	}
	c.Unavailable[1] = "mutated"
	if r.Core().Unavailable[1] != "identity" {
		t.Fatal("Core handed out the registry's own slice")
	}
	r.SetCore(Core{Degraded: "store sealed elsewhere", Unavailable: []string{"store", "identity"}})
	if signalled(ch) {
		t.Fatal("an unchanged condition woke the watcher")
	}
}
