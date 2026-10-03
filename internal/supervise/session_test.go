package supervise

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// userManifest is a per-user-console module.
func userManifest(caps ...string) *manifest.Manifest {
	m := testManifest(caps...)
	m.Privilege = manifest.PrivilegeUser
	m.Session = manifest.SessionPerUserConsole
	return m
}

// fixedSessions is a watcher that always reports one session.
type fixedSessions session.Session

func (f fixedSessions) Current() session.Snapshot {
	return session.Snapshot{Session: session.Session(f), OK: true, Changed: make(chan struct{})}
}

// console is a scriptable console: set what the source says, then Poll to
// broadcast it, as the real watcher's ticker would.
type console struct {
	*session.Watcher
	mu  sync.Mutex
	s   session.Session
	ok  bool
	err error
}

func newConsole(t *testing.T) *console {
	t.Helper()
	c := &console{}
	c.Watcher = session.NewWatcher(session.SourceFunc(func() (session.Session, bool, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.s, c.ok, c.err
	}), time.Hour, quietLog())
	return c
}

func (c *console) set(s session.Session, ok bool, err error) {
	c.mu.Lock()
	c.s, c.ok, c.err = s, ok, err
	c.mu.Unlock()
	c.Poll()
}

func TestPlacementError(t *testing.T) {
	cases := []struct {
		session, privilege, want string
	}{
		{manifest.SessionSystem, manifest.PrivilegeSystem, ""},
		{manifest.SessionSystem, manifest.PrivilegeService, ""},
		{manifest.SessionSystem, manifest.PrivilegeUser, "needs session"},
		{manifest.SessionPerUserConsole, manifest.PrivilegeUser, ""},
		{manifest.SessionPerUserConsole, manifest.PrivilegeSystem, "needs privilege"},
		{manifest.SessionPerUserConsole, manifest.PrivilegeService, "needs privilege"},
		{manifest.SessionPerUserAll, manifest.PrivilegeUser, "not supported"},
		{"elsewhere", manifest.PrivilegeUser, "unknown session"},
	}
	for _, c := range cases {
		err := placementError(&manifest.Manifest{Session: c.session, Privilege: c.privilege})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s/%s refused: %v", c.session, c.privilege, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s/%s = %v, want %q", c.session, c.privilege, err, c.want)
		}
	}
}

// A placement the supervisor will not honour is visible and never launched,
// which also fails an install's health gate.
func TestUnsupportedPlacementNeverLaunches(t *testing.T) {
	sup, _, _ := capturingSupervisor(t)
	mf := userManifest()
	mf.Session = manifest.SessionPerUserAll
	if err := sup.Add(Spec{Manifest: mf, BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	st := sup.Statuses()[0]
	if st.State != StateRequirementsUnmet || !strings.Contains(st.Detail, "per-user-all") {
		t.Fatalf("status = %s (%s)", st.State, st.Detail)
	}
}

func TestWaitingForSession(t *testing.T) {
	sup, _, cancel := capturingSupervisor(t)
	con := newConsole(t)
	sup.Sessions = con
	if err := sup.Add(Spec{Manifest: userManifest(), BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateWaitingForSession, 10*time.Second)
	if st.Detail != "no console user session" || st.PID != 0 {
		t.Fatalf("waiting status = %+v", st)
	}

	con.set(session.Session{}, false, errors.New("logind unreadable"))
	waitFor(t, sup, "probe failure detail", 10*time.Second, func(s Status) bool {
		return s.State == StateWaitingForSession &&
			strings.Contains(s.Detail, "console session unknown: logind unreadable")
	})

	cancel()
	sup.Wait()
	if st := sup.Statuses()[0]; st.State != StateStopped {
		t.Fatalf("after shutdown: %s", st.State)
	}
}

// The whole per-user lifecycle against a real module: start when a user is
// at the console, stop when they leave, start again in the next session,
// and move when the console changes hands.
func TestPerUserModuleFollowsTheConsole(t *testing.T) {
	canLaunchIntoSelf(t)
	sup, logs, cancel := capturingSupervisor(t)
	con := newConsole(t)
	sup.Sessions = con
	first := selfSession(t, 1)
	con.set(first, true, nil)

	if err := sup.Add(
		Spec{Manifest: userManifest("platform.osinfo"), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateRunning, 30*time.Second)
	if !strings.Contains(st.Detail, "console session "+first.ID) || st.PID == 0 {
		t.Fatalf("running status = %+v\n%s", st, logs)
	}

	con.set(session.Session{}, false, nil) // logout
	waitState(t, sup, StateWaitingForSession, 30*time.Second)

	con.set(first, true, nil) // back again
	st2 := waitState(t, sup, StateRunning, 30*time.Second)
	if st2.PID == st.PID {
		t.Fatal("module not restarted for the new session")
	}

	second := selfSession(t, 2) // fast user switch
	con.set(second, true, nil)
	waitFor(t, sup, "running in the second session", 30*time.Second, func(s Status) bool {
		return s.State == StateRunning && strings.Contains(s.Detail, "console session "+second.ID)
	})
	waitLog(t, logs, "module restarts in the next one", 5*time.Second)
	if st := sup.Statuses()[0]; st.Restarts != 0 {
		t.Fatalf("session changes counted as crashes: %d", st.Restarts)
	}

	cancel()
	sup.Wait()
	if st := sup.Statuses()[0]; st.State != StateStopped || st.Detail != "core shutting down" {
		t.Fatalf("after shutdown: %s (%s)", st.State, st.Detail)
	}
}

// The restart budget is per session: spent in one, it pins the module down
// until the console changes hands, then the next session gets a fresh one.
func TestStartLimitIsPerSession(t *testing.T) {
	sup, _, _ := capturingSupervisor(t)
	sup.Verifier = VerifierFunc(
		func(string, *manifest.Manifest) error { return errors.New("bad signature") },
	)
	con := newConsole(t)
	sup.Sessions = con
	con.set(selfSession(t, 1), true, nil)
	if err := sup.Add(
		Spec{Manifest: userManifest(), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	// The breaker reports itself first and the session loop then names the
	// session it is waiting out, so wait for the second detail rather than
	// the first start-limited state.
	st := waitFor(
		t,
		sup,
		"start-limited until the next session",
		30*time.Second,
		func(s Status) bool {
			return s.State == StateStartLimited &&
				strings.Contains(s.Detail, "waiting for the next session")
		},
	)
	spent := st.Restarts

	con.set(selfSession(t, 2), true, nil)
	waitFor(t, sup, "a fresh budget in the next session", 30*time.Second, func(s Status) bool {
		return s.Restarts > spent
	})
	waitState(t, sup, StateStartLimited, 30*time.Second)
}

// Shutdown while pinned by the start limit stops cleanly.
func TestStartLimitedShutdown(t *testing.T) {
	sup, _, cancel := capturingSupervisor(t)
	sup.Verifier = VerifierFunc(
		func(string, *manifest.Manifest) error { return errors.New("bad signature") },
	)
	sup.Sessions = fixedSessions(selfSession(t, 1))
	if err := sup.Add(Spec{Manifest: userManifest(), BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	waitState(t, sup, StateStartLimited, 30*time.Second)
	cancel()
	sup.Wait()
	if st := sup.Statuses()[0]; st.State != StateStopped {
		t.Fatalf("after shutdown: %s", st.State)
	}
}

// A protocol refusal is the binary's property, not the session's: terminal.
func TestPerUserUnsupportedProtocolIsTerminal(t *testing.T) {
	canLaunchIntoSelf(t)
	sup, _, _ := capturingSupervisor(t)
	sup.Window = handshake.Window{Min: 2, Max: 4}
	sup.Sessions = fixedSessions(selfSession(t, 1))
	if err := sup.Add(
		Spec{Manifest: userManifest("platform.osinfo"), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	waitState(t, sup, StateUnsupportedProtocol, 30*time.Second)
	sup.Wait()
	if st := sup.Statuses()[0]; st.State != StateUnsupportedProtocol {
		t.Fatalf("state = %s", st.State)
	}
}

// With no watcher configured the supervisor starts one over the platform
// source, once, on the run-lifetime context.
func TestDefaultSessionWatcher(t *testing.T) {
	orig := consoleSource
	t.Cleanup(func() { consoleSource = orig })
	calls := 0
	consoleSource = func() session.Source {
		calls++
		return session.SourceFunc(
			func() (session.Session, bool, error) { return session.Session{}, false, nil },
		)
	}
	sup, _, _ := capturingSupervisor(t)
	w := sup.sessions()
	if w == nil || sup.sessions() != w || calls != 1 {
		t.Fatalf("default watcher = %v, built %d times", w, calls)
	}
	if snap := w.Current(); snap.OK {
		t.Fatalf("snapshot = %+v", snap)
	}

	sup2, _, _ := capturingSupervisor(t)
	fixed := fixedSessions(session.Session{ID: "1"})
	sup2.Sessions = &fixed
	if sup2.sessions() != SessionWatcher(&fixed) {
		t.Fatal("configured watcher ignored")
	}
}
