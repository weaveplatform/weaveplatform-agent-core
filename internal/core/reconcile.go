package core

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"sync"
	"time"

	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Defaults for the reload loop. A package install unpacks a module's files
// one after another, each firing its own watch event; half a second of quiet
// is long enough for dpkg to finish a module and short enough that an operator
// does not notice. A stream of events that never goes quiet still gets a pass
// once debounceCeiling debounces have passed since its first event.
const (
	defaultDebounce = 500 * time.Millisecond
	debounceCeiling = 10
)

// Diff is what one module reload pass did.
type Diff struct {
	Added, Removed, Replaced []string
	// Invalid is every module directory that cannot run as things stand after
	// the pass, not only the ones this pass found.
	Invalid []InvalidModule
}

// InvalidModule is a module directory core will not run, and why.
type InvalidModule struct{ ID, Detail string }

func (d Diff) changed() bool {
	return len(d.Added)+len(d.Removed)+len(d.Replaced) > 0
}

// moduleLocker is the lifecycle manager's per-module install lock.
type moduleLocker interface {
	LockModule(id string) (unlock func())
}

type invalidEntry struct {
	detail string
	since  time.Time
}

// reconciler makes the supervisor run what the modules directory holds. Every
// trigger — start-up, SIGHUP, ControlService.Reload, the directory watch and
// the periodic rescan — ends in reconcile, so they cannot disagree about what
// a change means.
//
// Each module is compared and acted on under the lifecycle manager's lock for
// that id, so a reload and an install or rollback of the same module take
// turns: the install's promote is never seen half done. Passes are serialised;
// triggers arriving during one coalesce into the next.
type reconciler struct {
	log *slog.Logger
	dir string
	sup *supervise.Supervisor
	// lock is nil when nothing else installs modules (tests).
	lock moduleLocker
	// debounce is how long the directory must stay quiet after a trigger
	// before a pass; zero gets defaultDebounce.
	debounce time.Duration
	// rescan is the periodic pass, the safety net for a change no watch
	// reported; zero disables it.
	rescan time.Duration
	// afterPass, when set, is called after each pass run makes (tests).
	afterPass func()

	once sync.Once
	trig chan struct{}

	mu      sync.Mutex
	invalid map[string]invalidEntry
	skipped map[string]bool
}

func (r *reconciler) triggers() chan struct{} {
	r.once.Do(func() { r.trig = make(chan struct{}, 1) })
	return r.trig
}

// trigger asks for a pass after the debounce. It never blocks: one pending
// trigger is as good as many, since a pass reads the whole directory.
func (r *reconciler) trigger() {
	select {
	case r.triggers() <- struct{}{}:
	default:
	}
}

// run serves triggers and the periodic rescan until ctx ends.
func (r *reconciler) run(ctx context.Context) {
	debounce := r.debounce
	if debounce <= 0 {
		debounce = defaultDebounce
	}
	ceiling := debounceCeiling * debounce
	var tick <-chan time.Time
	if r.rescan > 0 {
		t := time.NewTicker(r.rescan)
		defer t.Stop()
		tick = t.C
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var first time.Time
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.triggers():
			now := time.Now()
			if !pending {
				pending, first = true, now
			}
			wait := min(debounce, max(ceiling-now.Sub(first), 0))
			timer.Reset(wait)
		// A pass registers modules on the supervisor's run-lifetime
		// context, never on this loop's.
		case <-timer.C:
			pending = false
			r.pass() //nolint:contextcheck // see above
		case <-tick:
			r.pass() //nolint:contextcheck // see above
		}
	}
}

func (r *reconciler) pass() {
	if _, err := r.reconcile(); err != nil {
		// The running set is left exactly as it was: see moduleDirs.
		r.log.Error("module reload failed", "dir", r.dir, "err", err)
	}
	if r.afterPass != nil {
		r.afterPass()
	}
}

// reconcile rereads the modules directory and applies the difference.
func (r *reconciler) reconcile() (Diff, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names, err := moduleDirs(r.dir)
	if err != nil {
		return Diff{}, err
	}
	ids := make(map[string]bool, len(names))
	for _, n := range names {
		ids[n] = true
	}
	for id := range r.sup.Specs() {
		ids[id] = true
	}
	for id := range r.invalid {
		ids[id] = true
	}
	for id := range r.skipped {
		ids[id] = true
	}

	var d Diff
	retry := false
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		unlock := func() {}
		if r.lock != nil {
			unlock = r.lock.LockModule(id)
		}
		// Read again under the lock: an install that held it may have
		// changed the directory since the listing.
		ent, found := loadModule(r.dir, id)
		retry = r.apply(id, ent, found, &d) || retry
		unlock()
	}
	if retry {
		r.trigger()
	}
	for _, id := range slices.Sorted(maps.Keys(r.invalid)) {
		d.Invalid = append(d.Invalid, InvalidModule{ID: id, Detail: r.invalid[id].detail})
	}
	if d.changed() {
		r.log.Info(
			"modules reloaded",
			"added",
			d.Added,
			"removed",
			d.Removed,
			"replaced",
			d.Replaced,
			"invalid",
			len(d.Invalid),
		)
	}
	return d, nil
}

// apply makes one module's supervision match its directory, and reports
// whether the directory was mid-write and needs another look.
func (r *reconciler) apply(id string, ent moduleEntry, found bool, d *Diff) (retry bool) {
	running, isRunning := r.sup.Specs()[id]
	switch {
	case found && ent.unsettled:
		r.log.Info("module binary changing; reloading it again shortly", "module", id)
		return true

	case found && ent.invalid != "":
		// What runs is what the directory says, and it no longer says
		// anything runnable — so the old process does not keep going on a
		// binary or config the directory may no longer hold.
		if isRunning {
			r.sup.StopModule(id)
		}
		r.setInvalid(id, ent.invalid)

	case !found || !ent.spec.Manifest.SupportsHost(runtime.GOOS, runtime.GOARCH):
		if found && !r.skipped[id] {
			r.log.Warn("module does not support this host; skipping",
				"module", id, "os", runtime.GOOS, "arch", runtime.GOARCH)
			if r.skipped == nil {
				r.skipped = make(map[string]bool)
			}
			r.skipped[id] = true
		}
		if !found {
			delete(r.skipped, id)
		}
		if isRunning {
			r.sup.StopModule(id)
			d.Removed = append(d.Removed, id)
			r.log.Info("module removed", "module", id)
		}
		r.clearInvalid(id)

	case !isRunning:
		delete(r.skipped, id)
		// Add only registers; the module runs on the supervisor's base
		// context, and is verified before exec like every launch.
		if err := r.sup.Add(ent.spec); err != nil {
			r.log.Error("registering module failed", "module", id, "err", err)
			r.setInvalid(id, err.Error())
			return false
		}
		delete(r.invalid, id)
		d.Added = append(d.Added, id)
		r.log.Info("module added", "module", id, "version", ent.spec.Manifest.Version)

	case specChanged(running, ent.spec):
		if err := r.sup.Replace(ent.spec); err != nil {
			r.log.Error("replacing module failed", "module", id, "err", err)
			r.setInvalid(id, err.Error())
			return false
		}
		d.Replaced = append(d.Replaced, id)
		r.log.Info("module replaced", "module", id,
			"from", running.Manifest.Version, "to", ent.spec.Manifest.Version)
	}
	return false
}

// specChanged is the reload's notion of "a different module": another
// version, another binary (in place or at another path, as a `current` flip
// gives) or another config. Anything else in the manifest is ignored, so a
// rewrite that changes nothing a module runs with does not restart it.
func specChanged(a, b supervise.Spec) bool {
	return a.Manifest.Version != b.Manifest.Version || a.BinPath != b.BinPath ||
		a.Digest != b.Digest || !bytes.Equal(a.Config, b.Config)
}

// setInvalid records id as invalid in the registry, so every view — hosts'
// modules.changed included — says the module is there and why it is not
// running. since holds while the reason does, so a rescan that finds the same
// fault does not wake every watcher to say nothing new.
func (r *reconciler) setInvalid(id, detail string) {
	if r.invalid == nil {
		r.invalid = make(map[string]invalidEntry)
	}
	e, had := r.invalid[id]
	if !had || e.detail != detail {
		e = invalidEntry{detail: detail, since: time.Now()}
		r.invalid[id] = e
		r.log.Error("module invalid", "module", id, "detail", detail)
	}
	r.sup.Modules().Set(registry.Module{
		ID: id, State: registry.StateInvalid, Detail: e.detail, Since: e.since,
	})
}

// clearInvalid drops an invalid entry whose directory has gone.
func (r *reconciler) clearInvalid(id string) {
	if _, had := r.invalid[id]; !had {
		return
	}
	delete(r.invalid, id)
	r.sup.Modules().Remove(id)
}

// reload is ControlService.Reload.
func (r *reconciler) reload(context.Context) (*controlv1.ReloadResponse, error) {
	// Modules outlive the RPC: they run on the supervisor's context.
	d, err := r.reconcile() //nolint:contextcheck // see above
	if err != nil {
		return nil, fmt.Errorf("reload: %w", err)
	}
	resp := &controlv1.ReloadResponse{Added: d.Added, Removed: d.Removed, Replaced: d.Replaced}
	for _, m := range d.Invalid {
		resp.Invalid = append(resp.Invalid, &controlv1.InvalidModule{Id: m.ID, Detail: m.Detail})
	}
	return resp, nil
}
