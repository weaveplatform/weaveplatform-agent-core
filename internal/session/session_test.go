package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// scripted is a Source whose answer the test sets.
type scripted struct {
	mu    sync.Mutex
	s     Session
	ok    bool
	err   error
	calls int
}

func (f *scripted) set(s Session, ok bool, err error) {
	f.mu.Lock()
	f.s, f.ok, f.err = s, ok, err
	f.mu.Unlock()
}

func (f *scripted) Console() (Session, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.s, f.ok, f.err
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestSessionEqual(t *testing.T) {
	a := Session{ID: "2", User: "alice", UID: 1000, Env: []string{"X=1"}}
	if !a.Equal(a) {
		t.Fatal("a session differs from itself")
	}
	for _, b := range []Session{
		{ID: "3", User: "alice", UID: 1000, Env: []string{"X=1"}},
		{ID: "2", User: "bob", UID: 1000, Env: []string{"X=1"}},
		{ID: "2", User: "alice", UID: 1001, Env: []string{"X=1"}},
		{ID: "2", User: "alice", UID: 1000, Env: []string{"X=1", "WAYLAND_DISPLAY=wayland-0"}},
	} {
		if a.Equal(b) {
			t.Fatalf("%+v equal to %+v", a, b)
		}
	}
}

// The first Current probes synchronously: no spurious "no session" before
// Run's first tick, and no change broadcast for the initial answer.
func TestWatcherFirstCurrentProbes(t *testing.T) {
	alice := Session{ID: "2", User: "alice", UID: 1000}
	src := &scripted{s: alice, ok: true}
	w := NewWatcher(src, 0, quiet)
	if w.interval != DefaultInterval {
		t.Fatalf("interval = %v", w.interval)
	}
	snap := w.Current()
	if !snap.OK || !snap.Session.Equal(alice) || snap.Err != nil {
		t.Fatalf("snapshot = %+v", snap)
	}
	if closed(snap.Changed) {
		t.Fatal("initial answer broadcast as a change")
	}
	w.Current()
	if src.calls != 1 {
		t.Fatalf("Current re-probed: %d calls", src.calls)
	}
}

func TestWatcherBroadcastsChanges(t *testing.T) {
	alice := Session{ID: "2", User: "alice", UID: 1000}
	bob := Session{ID: "5", User: "bob", UID: 1001}
	src := &scripted{s: alice, ok: true}
	w := NewWatcher(src, time.Hour, quiet)
	snap := w.Current()

	w.Poll() // same answer: nothing to say
	if closed(snap.Changed) {
		t.Fatal("unchanged poll broadcast")
	}

	src.set(bob, true, nil) // fast user switch
	w.Poll()
	if !closed(snap.Changed) {
		t.Fatal("user switch not broadcast")
	}
	snap = w.Current()
	if !snap.Session.Equal(bob) {
		t.Fatalf("after switch: %+v", snap.Session)
	}

	src.set(Session{}, false, nil) // logout
	w.Poll()
	if !closed(snap.Changed) {
		t.Fatal("logout not broadcast")
	}
	snap = w.Current()
	if snap.OK {
		t.Fatalf("after logout: %+v", snap)
	}

	// A failed probe reads as no session, carrying the error; the same
	// failure again is not news, a different one is.
	src.set(alice, true, errors.New("probe broke"))
	w.Poll()
	if !closed(snap.Changed) {
		t.Fatal("probe failure not broadcast")
	}
	snap = w.Current()
	if snap.OK || snap.Err == nil || snap.Session.User != "" {
		t.Fatalf("failed probe snapshot = %+v", snap)
	}
	w.Poll()
	if closed(snap.Changed) {
		t.Fatal("repeated identical failure broadcast")
	}
	src.set(alice, true, nil)
	w.Poll()
	if !closed(snap.Changed) {
		t.Fatal("recovery not broadcast")
	}
}

func TestWatcherRunPollsUntilCancelled(t *testing.T) {
	src := &scripted{}
	w := NewWatcher(src, 5*time.Millisecond, quiet)
	snap := w.Current()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	src.set(Session{ID: "1", User: "u", UID: 7}, true, nil)
	select {
	case <-snap.Changed:
	case <-time.After(5 * time.Second):
		t.Fatal("Run never noticed the login")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored cancellation")
	}
}

func TestSourceFunc(t *testing.T) {
	s, ok, err := SourceFunc(
		func() (Session, bool, error) { return Session{ID: "x"}, true, nil },
	).Console()
	if s.ID != "x" || !ok || err != nil {
		t.Fatalf("SourceFunc = %+v %v %v", s, ok, err)
	}
}

// The platform source answers without error wherever the tests run. Whether
// anyone is at the console depends on the runner, so only the shape of a
// positive answer is checked.
func TestPlatformConsole(t *testing.T) {
	s, ok, err := Console().Console()
	if err != nil {
		t.Fatalf("platform console probe: %v", err)
	}
	if ok && (s.ID == "" || s.User == "") {
		t.Fatalf("console session without identity: %+v", s)
	}
	t.Logf("console: ok=%v %+v", ok, s)
}
