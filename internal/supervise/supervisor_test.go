package supervise

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
)

func buildTestModule(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "testmod"+exeSuffix())
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/testmodule")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building test module: %v\n%s", err, out)
	}
	return bin
}

// exeSuffix: Windows cannot exec a binary without its extension.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func testManifest(caps ...string) *manifest.Manifest {
	return &manifest.Manifest{
		Schema:       1,
		ID:           "testmod",
		Version:      "0.0.1",
		Protocol:     1,
		Zone:         "A",
		Privilege:    manifest.PrivilegeService,
		Session:      manifest.SessionSystem,
		Platforms:    []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Capabilities: caps,
	}
}

func newTestSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// Not t.TempDir(): long test names push unix socket paths past the
	// 104-byte sun_path limit on macOS.
	dir, err := os.MkdirTemp("", "wv-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lay := layout.Resolve(dir)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}
	return &Supervisor{
		Log:    log,
		Window: handshake.Window{Min: 1, Max: 1},
		Caps:   capability.Probe(),
		Services: &hostserv.Services{
			Log:       log,
			Bus:       eventbus.New(),
			Store:     hostserv.NewMemStore(),
			Policy:    hostserv.NewMemPolicy(),
			Identity:  hostserv.NewStubIdentity(),
			Transport: &hostserv.LogTransport{Log: log},
		},
		Layout:   lay,
		Verifier: VerifierFunc(func(string, *manifest.Manifest) error { return nil }),
		Backoff: retry.Backoff{
			Initial: 20 * time.Millisecond,
			Max:     50 * time.Millisecond,
			Factor:  2,
		},
		StartLimitBurst:  3,
		StartLimitWindow: time.Minute,
		HealthInterval:   100 * time.Millisecond,
		LaunchTimeout:    15 * time.Second,
		StableAfter:      time.Hour, // never reset crash counts inside a test
	}
}

// waitFor polls until pred accepts the module's status or the deadline
// passes.
func waitFor(
	t *testing.T,
	sup *Supervisor,
	desc string,
	timeout time.Duration,
	pred func(Status) bool,
) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last Status
	for time.Now().Before(deadline) {
		for _, st := range sup.Statuses() {
			last = st
			if pred(st) {
				return st
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("module never reached %s; last: %+v", desc, last)
	return Status{}
}

// waitState polls until the module reaches want or the deadline passes.
func waitState(t *testing.T, sup *Supervisor, want State, timeout time.Duration) Status {
	t.Helper()
	return waitFor(t, sup, string(want), timeout, func(st Status) bool { return st.State == want })
}

func TestModuleRunsAndRestartsAfterKill(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateRunning, 15*time.Second)
	if st.PID == 0 {
		t.Fatal("running module has no PID")
	}

	// Kill it: the supervisor must notice, back off, and restart.
	proc, err := os.FindProcess(st.PID)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}

	st2 := waitFor(t, sup, "restarted and running", 15*time.Second, func(s Status) bool {
		return s.State == StateRunning && s.Restarts >= 1 && s.PID != st.PID
	})
	if st2.PID == 0 {
		t.Fatal("restarted module has no PID")
	}

	cancel()
	sup.Wait()
	final := sup.Statuses()[0]
	if final.State != StateStopped {
		t.Errorf("state after shutdown = %s, want stopped", final.State)
	}
}

// TestCoreRefusesOutOfWindowProtocol drives the REAL supervisor (not the
// testkit StubCore) with a window that excludes the module's protocol. The
// module must exit 78 before listening and the supervisor must record it as
// unsupported — no restart, no PID — proving the clean-refusal path on the
// production launch code, not just the fixture.
func TestCoreRefusesOutOfWindowProtocol(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	// The test module speaks protocol 1; advertise a window past it.
	sup.Window = handshake.Window{Min: 2, Max: 4}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateUnsupportedProtocol, 15*time.Second)
	if st.Restarts != 0 {
		t.Errorf(
			"unsupported-protocol module restarted %d times; refusal must be terminal",
			st.Restarts,
		)
	}
	if st.PID != 0 {
		t.Errorf("unsupported-protocol module has PID %d; it must never have listened", st.PID)
	}

	// Give it a beat to prove it stays refused, never flipping to running.
	time.Sleep(500 * time.Millisecond)
	final := sup.Statuses()[0]
	if final.State != StateUnsupportedProtocol {
		t.Fatalf("state = %s, want stable unsupported-protocol", final.State)
	}
}

// TestWatchdogSatisfiedByHealthyModule proves the push watchdog end to end:
// with an interval set and the Keepalive seam wired, a real module process
// pings on its own cadence, so the supervisor must NOT restart it.
// (A false positive here would mean the ping loop, the WatchdogService, or
// the monitor freshness check is broken.)
func TestWatchdogSatisfiedByHealthyModule(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	// Whole seconds: InitRequest carries the interval in seconds, so a
	// sub-second value truncates to zero (disabled).
	sup.WatchdogInterval = time.Second
	sup.Services.Watchdog = sup.Keepalive
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateRunning, 15*time.Second)

	// Observe across several watchdog deadlines (2×1s). A pinging module
	// stays up with the same PID and zero restarts.
	time.Sleep(3 * time.Second)
	final := sup.Statuses()[0]
	if final.State != StateRunning {
		t.Fatalf("healthy pinging module state = %s, want running", final.State)
	}
	if final.Restarts != 0 {
		t.Fatalf(
			"healthy pinging module restarted %d times; watchdog false positive",
			final.Restarts,
		)
	}
	if final.PID != st.PID {
		t.Fatalf(
			"PID changed (%d→%d): module was restarted under a satisfied watchdog",
			st.PID,
			final.PID,
		)
	}

	cancel()
	sup.Wait()
}

// TestWatchdogRestartsOnMissedPings proves the restart path fires: with the
// interval set but the Keepalive seam left unwired, the module's pings never
// advance the supervisor's liveness clock (as if the keepalive stream had
// broken), so once the deadline (2×interval) lapses the module is killed and
// relaunched.
func TestWatchdogRestartsOnMissedPings(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	sup.WatchdogInterval = time.Second
	// Deliberately do NOT wire sup.Services.Watchdog: pings arrive at core
	// but are dropped, so the liveness clock goes stale.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	waitState(t, sup, StateRunning, 15*time.Second)

	// Within a few deadlines the stale clock must force at least one restart.
	waitFor(t, sup, "watchdog-forced restart", 15*time.Second, func(s Status) bool {
		return s.Restarts >= 1
	})

	cancel()
	sup.Wait()
}

func TestBreakerTripsOnCrashLoop(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	t.Setenv("TESTMOD_EXIT_AFTER_MS", "50")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateStartLimited, 30*time.Second)
	if st.Restarts < 3 {
		t.Errorf("breaker tripped after %d restarts, want >= 3", st.Restarts)
	}
	cancel()
	sup.Wait()
}

func TestRequirementsUnmetNeverLaunches(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(
		Spec{Manifest: testManifest("no.such.capability"), BinPath: bin},
	); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateRequirementsUnmet, 5*time.Second)
	if st.PID != 0 {
		t.Errorf("gated module has a PID: it was launched")
	}
	cancel()
	sup.Wait()
}

func TestVerifierRefusalBlocksLaunch(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	sup.Verifier = VerifierFunc(func(path string, _ *manifest.Manifest) error {
		return os.ErrPermission
	})
	// A refused verify is a launch failure: backoff, then breaker. It must
	// never run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitState(t, sup, StateStartLimited, 30*time.Second)
	if st.PID != 0 {
		t.Errorf("refused module has a PID: it was executed")
	}
	cancel()
	sup.Wait()
}

func TestAddRefusesDuplicateID(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	spec := Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}
	if err := sup.Add(spec); err != nil {
		t.Fatal(err)
	}
	// A second Add for the same id must be refused rather than silently
	// overwriting the runner and orphaning the live process.
	if err := sup.Add(spec); err == nil {
		t.Fatal("duplicate Add accepted; the first runner would be orphaned")
	}
	cancel()
	sup.Wait()
}

func TestAddRefusesSharedChannelAddress(t *testing.T) {
	sup := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	// Gated on a capability no host has, so neither is launched: the refusal
	// is about registration alone.
	first := testManifest("never.present")
	first.ID, first.Address = "cap-linux", "cap.exec"
	if err := sup.Add(Spec{Manifest: first}); err != nil {
		t.Fatal(err)
	}
	second := testManifest("never.present")
	second.ID, second.Address = "cap-windows", "cap.exec"
	err := sup.Add(Spec{Manifest: second})
	if err == nil || !strings.Contains(err.Error(), `channel address "cap.exec"`) {
		t.Fatalf("shared address: err = %v", err)
	}
	// An id doubles as the address of a module that sets none.
	plain := testManifest("never.present")
	plain.ID = "plain"
	if err := sup.Add(Spec{Manifest: plain}); err != nil {
		t.Fatal(err)
	}
	third := testManifest("never.present")
	third.ID, third.Address = "other", "plain"
	if err := sup.Add(Spec{Manifest: third}); err == nil {
		t.Fatal("address equal to an address-less module's id accepted")
	}
	cancel()
	sup.Wait()
}

func TestAddRequiresBaseContext(t *testing.T) {
	bin := buildTestModule(t)
	sup := newTestSupervisor(t)
	// No SetBaseContext: Add must refuse rather than derive a runner from
	// a nil (or per-call) context.
	if err := sup.Add(Spec{Manifest: testManifest("platform.osinfo"), BinPath: bin}); err == nil {
		t.Fatal("Add accepted without a base context")
	}
}
