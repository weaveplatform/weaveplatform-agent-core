// Package supervise owns module processes: spawn, verify-before-exec,
// handshake, health, crash-loop damping, and a start-limit (restart budget).
// It fails
// closed: a module that cannot run safely does not run.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

var (
	errNoBaseContext     = errors.New("supervise: SetBaseContext not called before Add")
	errAlreadyRegistered = errors.New("already registered")
	errAddressTaken      = errors.New("already taken")

	// Placement refusals (placementError).
	errNeedsConsoleSession  = errors.New("runs as the console user and needs session")
	errNeedsUserPrivilege   = errors.New("runs as the console user and needs privilege")
	errPlacementUnsupported = errors.New("is not supported")
	errUnknownPlacement     = errors.New("unknown session placement")

	// errNoSystemIdentity: a privilege with no system-session account.
	errNoSystemIdentity = errors.New("has no system-session identity")
)

// Spec is one module the supervisor should run.
type Spec struct {
	Manifest *manifest.Manifest
	BinPath  string
	// Config is delivered opaquely in InitRequest.
	Config []byte
	// Digest is the binary's "sha256:<hex>" when the spec was built. Add
	// fills it in when empty, so whatever compares a running module with the
	// disk (core's module reload) can tell a binary replaced in place.
	Digest string
}

// Supervisor runs a set of modules. Configure the exported fields before
// Run; they are not mutated afterwards.
type Supervisor struct {
	Log      *slog.Logger
	Window   handshake.Window
	Caps     capability.Set
	Services *hostserv.Services
	Layout   layout.Layout
	Verifier Verifier

	// Backoff dampens restarts. Zero value gets retry.New().
	Backoff retry.Backoff
	// StartLimitBurst restarts within StartLimitWindow trip the breaker.
	// Zero gets 5 in 10 minutes.
	StartLimitBurst  int
	StartLimitWindow time.Duration
	// HealthInterval is the default poll cadence when a module doesn't
	// request one. Zero gets 30s.
	HealthInterval time.Duration
	// HealthStrikes consecutive failed polls restart the module. Zero
	// gets 3.
	HealthStrikes int
	// LaunchTimeout bounds spawn-to-handshake. Zero gets 10s.
	LaunchTimeout time.Duration
	// StableAfter is how long a module must stay up before its crash
	// count resets. Zero gets 60s.
	StableAfter time.Duration
	// WatchdogInterval is the cadence core asks modules to ping via
	// WatchdogService (sd_notify WATCHDOG shape). A module that misses two
	// intervals is restarted — this catches a hung-but-alive module that
	// answers Health from a separate goroutine. Zero disables the watchdog.
	WatchdogInterval time.Duration
	// Sessions reports the console user session that per-user-console
	// modules run in. Nil gets a watcher over the platform source, started
	// on the run-lifetime context the first time a per-user module needs it.
	Sessions SessionWatcher
	// Registry is where the supervisor records every module it holds, for
	// core's other components and its callers to read. Nil gets a private
	// one, reachable through Modules.
	Registry *registry.Registry

	// baseCtx is the run-lifetime context every runner derives from. It
	// is deliberately NOT the caller's context on Add/Replace: an install
	// or rollback arrives on a per-RPC context that is cancelled the
	// moment the RPC returns, and a module's lifetime must outlive the
	// call that installed it. Set once via SetBaseContext before Add.
	baseCtx context.Context

	mu      sync.Mutex
	runners map[string]*runner
	watcher SessionWatcher
}

// Modules returns the registry the supervisor records into.
func (s *Supervisor) Modules() *registry.Registry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Registry == nil {
		s.Registry = registry.New()
	}
	return s.Registry
}

// SessionWatcher is the supervisor's view of the console session;
// *session.Watcher implements it.
type SessionWatcher interface {
	Current() session.Snapshot
}

// consoleSource is the platform's console-session source, a seam so tests
// can exercise the default watcher without depending on who is logged in.
var consoleSource = session.Console

// sessions returns the configured watcher, or starts the platform one.
func (s *Supervisor) sessions() SessionWatcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watcher == nil {
		if s.Sessions != nil {
			s.watcher = s.Sessions
		} else {
			w := session.NewWatcher(consoleSource(), 0, s.Log)
			go w.Run(s.baseCtx)
			s.watcher = w
		}
	}
	return s.watcher
}

// SetBaseContext records the run-lifetime context. Call once, from
// core startup, before any Add. Modules live and die with this context,
// not with the context of whatever operation spawned them.
func (s *Supervisor) SetBaseContext(ctx context.Context) {
	s.mu.Lock()
	s.baseCtx = ctx
	s.mu.Unlock()
}

func (s *Supervisor) launchTimeout() time.Duration {
	if s.LaunchTimeout > 0 {
		return s.LaunchTimeout
	}
	return 10 * time.Second
}

func (s *Supervisor) startLimitBurst() int {
	if s.StartLimitBurst > 0 {
		return s.StartLimitBurst
	}
	return 5
}

func (s *Supervisor) startLimitWindow() time.Duration {
	if s.StartLimitWindow > 0 {
		return s.StartLimitWindow
	}
	return 10 * time.Minute
}

func (s *Supervisor) healthInterval() time.Duration {
	if s.HealthInterval > 0 {
		return s.HealthInterval
	}
	return 30 * time.Second
}

func (s *Supervisor) healthStrikes() int {
	if s.HealthStrikes > 0 {
		return s.HealthStrikes
	}
	return 3
}

func (s *Supervisor) stableAfter() time.Duration {
	if s.StableAfter > 0 {
		return s.StableAfter
	}
	return 60 * time.Second
}

func (s *Supervisor) backoff() retry.Backoff {
	if s.Backoff != (retry.Backoff{}) {
		return s.Backoff
	}
	return retry.New()
}

// watchdogInterval is the module ping cadence; zero means the watchdog is
// disabled (no default — core opts in explicitly).
func (s *Supervisor) watchdogInterval() time.Duration {
	return s.WatchdogInterval
}

// Keepalive records a watchdog ping from the named module. Called from the
// hostserv WatchdogService handler on the module's own cadence.
func (s *Supervisor) Keepalive(module string) {
	s.mu.Lock()
	r := s.runners[module]
	s.mu.Unlock()
	if r != nil {
		r.keepalive.Store(time.Now().UnixNano())
	}
}

func (s *Supervisor) capabilityList() []*agentv1.Capability {
	out := make([]*agentv1.Capability, 0, len(s.Caps))
	for name, attrs := range s.Caps {
		out = append(out, &agentv1.Capability{Name: name, Attributes: attrs})
	}
	return out
}

// Add registers and launches a module on the run-lifetime context. Pre-launch
// gates run here: platform support and the capability probe. Gated modules are
// registered (visible to operators) but never launched. Adding an id that is
// already registered is refused — callers hot-swap via Replace, which stops the
// incumbent first.
func (s *Supervisor) Add(spec Spec) error {
	if spec.Digest == "" {
		// Unreadable is not fatal here: launch reports it, with the rest of
		// what verify-before-exec finds.
		spec.Digest, _ = FileDigest(spec.BinPath)
	}
	s.mu.Lock()
	if s.baseCtx == nil {
		s.mu.Unlock()
		return errNoBaseContext
	}
	if s.runners == nil {
		s.runners = make(map[string]*runner)
	}
	if _, exists := s.runners[spec.Manifest.ID]; exists {
		s.mu.Unlock()
		return fmt.Errorf("supervise: module %q %w", spec.Manifest.ID, errAlreadyRegistered)
	}
	// Inbound channel frames fan out to every receiver under an address, so
	// two modules answering to one would both act on each request.
	addr := spec.Manifest.ChannelAddress()
	for id, other := range s.runners {
		if other.spec.Manifest.ChannelAddress() == addr {
			s.mu.Unlock()
			return fmt.Errorf("supervise: module %q answers to channel address %q, %w by %q",
				spec.Manifest.ID, addr, errAddressTaken, id)
		}
	}
	if s.Registry == nil {
		s.Registry = registry.New()
	}
	runCtx, cancel := context.WithCancel(s.baseCtx)
	r := &runner{
		sup:    s,
		reg:    s.Registry,
		spec:   spec,
		log:    s.Log.With("module", spec.Manifest.ID),
		state:  StatePending,
		since:  time.Now(),
		cancel: cancel,
	}
	s.runners[spec.Manifest.ID] = r
	s.mu.Unlock()
	r.mu.Lock()
	r.publishLocked()
	r.mu.Unlock()

	if err := placementError(spec.Manifest); err != nil {
		r.setState(StateRequirementsUnmet, err.Error())
		r.log.Warn("module not launched: unsupported placement", "err", err)
		cancel()
		return nil
	}
	if missing := s.Caps.Has(spec.Manifest.Capabilities...); len(missing) > 0 {
		r.setState(StateRequirementsUnmet, "missing capabilities: "+strings.Join(missing, ", "))
		r.log.Warn("module not launched: requirements unmet", "missing", missing)
		cancel() // gated module never runs; don't leak the context.
		return nil
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(runCtx)
	}()
	return nil
}

// StopModule winds one module down (drain, shutdown, kill after grace)
// and unregisters it. No-op for unknown ids.
func (s *Supervisor) StopModule(id string) {
	s.mu.Lock()
	r := s.runners[id]
	delete(s.runners, id)
	s.mu.Unlock()
	if r == nil {
		return
	}
	r.cancel()
	r.wg.Wait()
	// After the runner has finished, not before: its last state change
	// would otherwise put the entry straight back.
	r.reg.Remove(id)
	// The staged copy goes with the process, so a module removed from disk
	// leaves nothing runnable behind.
	if s.Layout.ExecDir == "" {
		return
	}
	if err := removeStaged(s.Layout.ModuleExecDir(id)); err != nil {
		r.log.Warn("staged binary left behind; swept at next start", "err", err)
	}
}

// Replace hot-swaps a module: the old process drains and stops, then the
// new spec starts on the run-lifetime context. The caller health-gates the
// result and rolls back on failure.
func (s *Supervisor) Replace(spec Spec) error {
	s.StopModule(spec.Manifest.ID)
	return s.Add(spec)
}

// SweepOrphans clears leftover per-module socket dirs and staged binaries
// from a previous core instance. Call once, before any Add.
func (s *Supervisor) SweepOrphans() {
	for _, dir := range []string{filepath.Join(s.Layout.RunDir, "modules"), s.Layout.ExecDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// Specs returns the spec of every module the supervisor holds, by id.
func (s *Supervisor) Specs() map[string]Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Spec, len(s.runners))
	for id, r := range s.runners {
		out[id] = r.spec
	}
	return out
}

// Statuses snapshots every registered module, sorted by id.
func (s *Supervisor) Statuses() []Status {
	_, out := s.Modules().List()
	return out
}

// Wait blocks until every runner has wound down (after ctx cancellation).
func (s *Supervisor) Wait() {
	s.mu.Lock()
	runners := make([]*runner, 0, len(s.runners))
	for _, r := range s.runners {
		runners = append(runners, r)
	}
	s.mu.Unlock()
	for _, r := range runners {
		r.wg.Wait()
	}
}

// runner is one module's supervision loop.
type runner struct {
	sup    *Supervisor
	reg    *registry.Registry
	spec   Spec
	log    *slog.Logger
	wg     sync.WaitGroup
	cancel context.CancelFunc

	// keepalive is the unix-nanos time of the last watchdog ping, stamped
	// by the hostserv WatchdogService handler and read by monitor. Atomic
	// because the two run on different goroutines.
	keepalive atomic.Int64

	mu       sync.Mutex
	state    State
	detail   string
	since    time.Time
	pid      int
	restarts uint32
	health   *agentv1.Health
	protocol uint32
	surfaces []*agentv1.Surface
}

func (r *runner) setState(st State, detail string) {
	r.mu.Lock()
	r.state = st
	r.detail = detail
	r.since = time.Now()
	r.publishLocked()
	r.mu.Unlock()
}

// publishLocked records the runner's current state in the registry. Called
// under r.mu so two changes cannot reach the registry in the opposite order
// to the one they happened in.
func (r *runner) publishLocked() {
	m := r.spec.Manifest
	r.reg.Set(Status{
		ID:           m.ID,
		Version:      m.Version,
		Protocol:     r.protocol,
		Address:      m.ChannelAddress(),
		Capabilities: slices.Clone(m.Capabilities),
		Privilege:    m.Privilege,
		Session:      m.Session,
		State:        r.state,
		Detail:       r.detail,
		PID:          r.pid,
		Restarts:     r.restarts,
		Health:       r.health,
		Since:        r.since,
		Surfaces:     r.surfaces,
	})
}

// placementError refuses manifests whose session and privilege the
// supervisor will not honour together. per-user-console and privilege "user"
// imply each other: a module in a user's session runs as that user — never
// as root, never as the service account — and "user" privilege has no user
// to run as outside a session.
//
// per-user-all is refused rather than approximated. It means one instance per
// logged-in session — background fast-user-switch sessions, RDP and SSH logins
// included — and the supervisor's model is one runner, one host-service
// identity and one store namespace per module id; several live instances of
// one id would share all three. Nothing needs it yet: the modules that want a
// session (clipboard, display, input) want the one at the console.
func placementError(m *manifest.Manifest) error {
	switch m.Session {
	case manifest.SessionSystem:
		if m.Privilege == manifest.PrivilegeUser {
			return fmt.Errorf("privilege %q %w %q",
				m.Privilege, errNeedsConsoleSession, manifest.SessionPerUserConsole)
		}
	case manifest.SessionPerUserConsole:
		if m.Privilege != manifest.PrivilegeUser {
			return fmt.Errorf("session %q %w %q, not %q",
				m.Session, errNeedsUserPrivilege, manifest.PrivilegeUser, m.Privilege)
		}
	case manifest.SessionPerUserAll:
		return fmt.Errorf("session placement %q %w: only %q runs in user sessions",
			m.Session, errPlacementUnsupported, manifest.SessionPerUserConsole)
	default:
		return fmt.Errorf("%w %q", errUnknownPlacement, m.Session)
	}
	return nil
}

// outcome is how one supervision run ended.
type outcome int

const (
	// outStopped: the run's context ended — core shutdown, operator stop, or
	// (for a per-user module) the console session going away.
	outStopped outcome = iota
	// outStartLimited: the restart budget is spent.
	outStartLimited
	// outUnsupported: the module refused the protocol window; terminal.
	outUnsupported
)

// run is the per-module state machine.
func (r *runner) run(ctx context.Context) {
	if r.spec.Manifest.Session == manifest.SessionPerUserConsole {
		r.runPerSession(ctx)
		return
	}
	r.superviseIn(ctx, nil, func() string { return "core shutting down" })
}

// runPerSession follows the console: wait for a user session, supervise the
// module inside it, and when the session ends or changes hands, stop the
// module and start over in whatever comes next. Each session start is a
// fresh supervision run — its own backoff and its own start limit — because a
// module that crash-looped in one user's session has said nothing about the
// next user's.
func (r *runner) runPerSession(ctx context.Context) {
	w := r.sup.sessions()
	for {
		snap := w.Current()
		if !snap.OK {
			detail := "no console user session"
			if snap.Err != nil {
				detail = "console session unknown: " + snap.Err.Error()
			}
			r.setState(StateWaitingForSession, detail)
			select {
			case <-snap.Changed:
				continue
			case <-ctx.Done():
				r.setState(StateStopped, "core shutting down")
				return
			}
		}

		sess := snap.Session
		sctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-snap.Changed:
				cancel()
			case <-sctx.Done():
			}
		}()
		out := r.superviseIn(sctx, &sess, func() string {
			if ctx.Err() != nil {
				return "core shutting down"
			}
			return "console session " + sess.ID + " ended"
		})
		cancel()

		switch {
		case ctx.Err() != nil:
			r.setState(StateStopped, "core shutting down")
			return
		case out == outUnsupported:
			return
		case out == outStartLimited:
			r.setState(StateStartLimited,
				"start limit reached in console session "+sess.ID+"; waiting for the next session")
			select {
			case <-snap.Changed:
			case <-ctx.Done():
				r.setState(StateStopped, "core shutting down")
				return
			}
		default:
			r.log.Info(
				"console session changed; module restarts in the next one",
				"session",
				sess.ID,
			)
		}
	}
}

// superviseIn runs launch → monitor → (backoff → relaunch)* until ctx ends,
// the restart budget is spent, or the module refuses the protocol. sess is
// nil for system modules. stopReason explains a ctx-ended stop.
func (r *runner) superviseIn(
	ctx context.Context,
	sess *session.Session,
	stopReason func() string,
) outcome {
	var crashes []time.Time
	attempt := 0
	backoff := r.sup.backoff()
	runningDetail := ""
	if sess != nil {
		runningDetail = "console session " + sess.ID + " (" + sess.User + ")"
	}

	for {
		if ctx.Err() != nil {
			r.setState(StateStopped, stopReason())
			return outStopped
		}
		r.setState(StateStarting, runningDetail)
		p, err := r.launch(ctx, sess)
		if err != nil {
			switch {
			case errors.Is(err, errProtocolUnsupported):
				r.setState(StateUnsupportedProtocol, "")
				r.log.Error("module refused protocol window; not restarting")
				return outUnsupported
			case ctx.Err() != nil:
				r.setState(StateStopped, stopReason())
				return outStopped
			}
			r.log.Error("launch failed", "err", err)
		} else {
			r.mu.Lock()
			r.pid = p.child.pid
			r.protocol = p.line.Protocol
			r.surfaces = p.initResp.GetSurfaces()
			r.mu.Unlock()
			r.setState(StateRunning, runningDetail)
			r.log.Info("module running", "pid", p.child.pid, "protocol", p.line.Protocol)

			startedAt := time.Now()
			clean := r.monitor(ctx, p)
			if clean {
				r.setState(StateStopped, stopReason())
				return outStopped
			}
			if time.Since(startedAt) >= r.sup.stableAfter() {
				attempt = 0
				crashes = nil
			}
		}

		// Crash accounting and the breaker.
		now := time.Now()
		crashes = append(crashes, now)
		pruned := crashes[:0]
		for _, t := range crashes {
			if now.Sub(t) <= r.sup.startLimitWindow() {
				pruned = append(pruned, t)
			}
		}
		crashes = pruned
		r.mu.Lock()
		r.restarts++
		r.publishLocked()
		r.mu.Unlock()
		if len(crashes) >= r.sup.startLimitBurst() {
			r.setState(StateStartLimited, "start limit reached: restarts exhausted")
			r.log.Error("start limit reached; not restarting",
				"crashes", len(crashes), "window", r.sup.startLimitWindow())
			return outStartLimited
		}

		delay := backoff.Delay(attempt)
		attempt++
		r.setState(StateBackoff, "restarting after "+delay.Round(time.Millisecond).String())
		r.log.Warn("module down; backing off", "delay", delay, "attempt", attempt)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			r.setState(StateStopped, stopReason())
			return outStopped
		}
	}
}

// monitor waits on the process, polling health. Returns true when the exit
// was a clean, requested stop (ctx cancelled), false for crashes.
func (r *runner) monitor(ctx context.Context, p *proc) bool {
	interval := r.sup.healthInterval()
	if s := p.initResp.GetHealthIntervalSeconds(); s > 0 {
		interval = time.Duration(s) * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Watchdog: if enabled, a module that has not pinged within two
	// intervals is restarted, catching a hung-but-alive module that still
	// answers Health on a separate goroutine. Seed the clock at launch so
	// the module gets a full deadline to send its first ping.
	wdInterval := r.sup.watchdogInterval()
	var wdTicker *time.Ticker
	var wdC <-chan time.Time
	if wdInterval > 0 {
		r.keepalive.Store(time.Now().UnixNano())
		wdTicker = time.NewTicker(wdInterval)
		defer wdTicker.Stop()
		wdC = wdTicker.C
	}

	// Poll once immediately so r.health is populated within the launch
	// rather than after a full interval — the promote health gate depends
	// on seeing a status promptly, and the default interval is 30s.
	strikes := 0
	if r.pollHealth(ctx, p, &strikes) {
		p.kill()
		return false
	}
	for {
		select {
		case <-ctx.Done():
			r.log.Info("stopping module")
			p.stop(ctx, r.log)
			return true
		case err := <-p.exited:
			p.teardown()
			r.log.Warn("module exited", "err", err)
			return false
		case <-ticker.C:
			if r.pollHealth(ctx, p, &strikes) {
				p.kill()
				return false
			}
		case <-wdC:
			last := time.Unix(0, r.keepalive.Load())
			if time.Since(last) > 2*wdInterval {
				r.log.Warn("watchdog deadline missed; restarting module",
					"last_ping", last, "deadline", 2*wdInterval)
				p.kill()
				return false
			}
		}
	}
}

// pollHealth performs one health check, records the status, and returns
// true when accumulated strikes mean the module should be restarted.
func (r *runner) pollHealth(ctx context.Context, p *proc, strikes *int) (restart bool) {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resp, err := p.client.Health(hctx, &agentv1.HealthRequest{})
	cancel()
	if err != nil {
		*strikes++
		r.log.Warn("health poll failed", "err", err, "strikes", *strikes)
	} else {
		h := resp.GetHealth()
		r.mu.Lock()
		r.health = h
		r.publishLocked()
		r.mu.Unlock()
		switch h.GetStatus() {
		case agentv1.Health_STATUS_UNHEALTHY:
			*strikes++
			r.log.Warn("module unhealthy", "reason", h.GetReason(), "strikes", *strikes)
		case agentv1.Health_STATUS_DEGRADED:
			*strikes = 0
			r.log.Info("module degraded", "reason", h.GetReason())
		default:
			*strikes = 0
		}
	}
	return *strikes >= r.sup.healthStrikes()
}
