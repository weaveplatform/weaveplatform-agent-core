// Package session reports which user owns the console — the logged-in user
// whose desktop is on the physical display — so the supervisor can run
// per-user-console modules inside that user's session.
//
// One Source per OS answers "who is at the console right now"; the Watcher
// polls it and tells subscribers when the answer changes. Polling, not OS
// notifications: every OS has a different notification mechanism (SCDynamicStore
// callbacks need a run loop, logind signals need D-Bus, WTS notifications need a
// window or a service control handler), and a console switch is a human-speed
// event — a two-second poll costs nothing and is the same code everywhere.
package session

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Session is one console user session.
type Session struct {
	// ID identifies the session itself, not the user: a logout and login of
	// the same user is a different session and must restart its modules.
	// logind session id on Linux, the launchd GUI domain (gui/<uid>) on macOS,
	// the WTS session id on Windows.
	ID string
	// User is the account name (DOMAIN\user on Windows).
	User string
	// UID is the unix uid; zero on Windows, where the token carries identity.
	UID uint32
	// Env is what a process needs to reach the session's desktop and bus that
	// the user's own environment does not already say — on Linux
	// XDG_RUNTIME_DIR, WAYLAND_DISPLAY/DISPLAY, DBUS_SESSION_BUS_ADDRESS. Empty
	// where launching into the session supplies it (macOS, Windows).
	Env []string
}

// Equal reports whether two sessions are the same for supervision purposes.
// Env is part of it: a Wayland socket that appears a moment after login is a
// change the module must be restarted to see.
func (s Session) Equal(o Session) bool {
	return s.ID == o.ID && s.User == o.User && s.UID == o.UID && slices.Equal(s.Env, o.Env)
}

// Source reports the current console session. ok is false when nobody is
// logged in at the console (login window, greeter, headless host).
type Source interface {
	Console() (s Session, ok bool, err error)
}

// SourceFunc adapts a function to Source.
type SourceFunc func() (Session, bool, error)

// Console implements Source.
func (f SourceFunc) Console() (Session, bool, error) { return f() }

// Snapshot is the watcher's view at one moment.
type Snapshot struct {
	Session Session
	OK      bool
	// Err is the probe failure, if the last poll failed. A failed probe is
	// reported as no session: running a module in a session core cannot see
	// is how it ends up in the wrong user's desktop.
	Err error
	// Changed is closed when a later poll sees something different.
	Changed <-chan struct{}
}

// DefaultInterval is how often the Watcher re-probes the console.
const DefaultInterval = 2 * time.Second

// Watcher polls a Source and broadcasts changes.
type Watcher struct {
	src      Source
	interval time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	polled  bool
	cur     Session
	ok      bool
	err     error
	changed chan struct{}
}

// NewWatcher returns a watcher over src. A zero interval gets DefaultInterval.
func NewWatcher(src Source, interval time.Duration, log *slog.Logger) *Watcher {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Watcher{src: src, interval: interval, log: log, changed: make(chan struct{})}
}

// Current returns the latest snapshot. The first call probes synchronously,
// so a caller never sees a spurious "no session" just because Run has not
// polled yet.
func (w *Watcher) Current() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.polled {
		w.pollLocked()
	}
	return Snapshot{Session: w.cur, OK: w.ok, Err: w.err, Changed: w.changed}
}

// Run polls until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		w.Poll()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll probes once and broadcasts if anything changed.
func (w *Watcher) Poll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pollLocked()
}

func (w *Watcher) pollLocked() {
	s, ok, err := w.src.Console()
	if err != nil || !ok {
		s, ok = Session{}, false
	}
	if w.polled && ok == w.ok && s.Equal(w.cur) && errText(err) == errText(w.err) {
		return
	}
	first := !w.polled
	w.polled = true
	w.cur, w.ok, w.err = s, ok, err
	switch {
	case err != nil:
		w.log.Warn("console session probe failed", "err", err)
	case ok:
		w.log.Info("console session", "id", s.ID, "user", s.User)
	case !first:
		w.log.Info("console session ended")
	}
	if !first {
		close(w.changed)
		w.changed = make(chan struct{})
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
