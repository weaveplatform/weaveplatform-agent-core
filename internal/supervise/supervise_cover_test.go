package supervise

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
)

// childSleepEnv turns the test binary into a long-sleeping child, for tests
// that need a real process to contain or kill.
const childSleepEnv = "SUPERVISE_TEST_CHILD_SLEEP"

// childEchoEnv turns the test binary into a child that writes a line to
// each of stdout and stderr, echoes the named variable, and exits 3.
const childEchoEnv = "SUPERVISE_TEST_CHILD_ECHO"

var (
	fixtureDir  string
	fixtureOnce sync.Once
	fixtureErr  error
	fixtureBins = map[string]string{}
)

func TestMain(m *testing.M) {
	if os.Getenv(childSleepEnv) == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if v := os.Getenv(childEchoEnv); v != "" {
		fmt.Fprintf(os.Stdout, "out %s=%s\n", v, os.Getenv(v))
		fmt.Fprintln(os.Stderr, "err line")
		os.Exit(3)
	}
	code := m.Run()
	if fixtureDir != "" {
		os.RemoveAll(fixtureDir) //nolint:errcheck
	}
	os.Exit(code)
}

// fixture builds the named testdata program once per test binary run;
// the integration tests below would otherwise pay a build each.
func fixture(t *testing.T, name string) string {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureDir, fixtureErr = os.MkdirTemp("", "wvfx-*")
		if fixtureErr != nil {
			return
		}
		for _, n := range []string{"testmodule", "rawmodule"} {
			bin := filepath.Join(fixtureDir, n+exeSuffix())
			cmd := exec.Command("go", "build", "-o", bin, "./testdata/"+n)
			cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				fixtureErr = fmt.Errorf("building %s: %v\n%s", n, err, out)
				return
			}
			fixtureBins[n] = bin
		}
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixtureBins[name]
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// capturingSupervisor is newTestSupervisor with its log captured at debug.
func capturingSupervisor(t *testing.T) (*Supervisor, *syncBuffer, context.CancelFunc) {
	t.Helper()
	sup := newTestSupervisor(t)
	logs := &syncBuffer{}
	sup.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	sup.SetBaseContext(ctx)
	t.Cleanup(func() {
		cancel()
		sup.Wait()
	})
	return sup, logs, cancel
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitLog(t *testing.T, logs *syncBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q:\n%s", want, logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDefaults(t *testing.T) {
	var s Supervisor
	if s.launchTimeout() != 10*time.Second || s.startLimitBurst() != 5 ||
		s.startLimitWindow() != 10*time.Minute || s.healthInterval() != 30*time.Second ||
		s.healthStrikes() != 3 || s.stableAfter() != 60*time.Second || s.backoff() != retry.New() {
		t.Fatal("zero-value supervisor does not get the documented defaults")
	}
	s.HealthStrikes = 7
	if s.healthStrikes() != 7 {
		t.Fatal("configured strikes ignored")
	}
}

func TestPrivilegeLevel(t *testing.T) {
	for priv, want := range map[string]agentv1.PrivilegeLevel{
		manifest.PrivilegeSystem:  agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_SYSTEM,
		manifest.PrivilegeUser:    agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_USER,
		manifest.PrivilegeService: agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_SERVICE,
	} {
		if got := privilegeLevel(&manifest.Manifest{Privilege: priv}); got != want {
			t.Errorf("privilegeLevel(%s) = %v, want %v", priv, got, want)
		}
	}
}

func TestLineCapture(t *testing.T) {
	ch := make(chan string, 1)
	w := &lineCapture{ch: ch, max: 16}
	w.Write([]byte("WEAVE|1"))             //nolint:errcheck
	w.Write([]byte("|1|unix|/s\nmore\n"))  //nolint:errcheck
	w.Write([]byte("after the handshake")) //nolint:errcheck
	if got := <-ch; got != "WEAVE|1|1|unix|/s" {
		t.Fatalf("first line = %q", got)
	}

	// Over the cap with no newline: an empty line, which fails to parse.
	ch2 := make(chan string, 1)
	w2 := &lineCapture{ch: ch2, max: 4}
	w2.Write([]byte("xxxxxxxx")) //nolint:errcheck
	if got := <-ch2; got != "" {
		t.Fatalf("over-cap line = %q, want empty", got)
	}

	// Nobody listening (launch already gave up): emit must not block.
	w3 := &lineCapture{ch: make(chan string), max: 0}
	done := make(chan struct{})
	go func() {
		w3.Write([]byte("line\n")) //nolint:errcheck
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lineCapture blocked on an unread channel")
	}
}

func TestSweepOrphans(t *testing.T) {
	sup := newTestSupervisor(t)
	sup.SweepOrphans() // nothing there yet
	stale := sup.Layout.ModuleRunDir("old")
	staged := filepath.Join(sup.Layout.RunDir, "bin", "old")
	for _, d := range []string{stale, staged} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sup.SweepOrphans()
	for _, d := range []string{stale, staged} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("orphan %s survived: %v", d, err)
		}
	}
}

func TestReplaceAndStopModule(t *testing.T) {
	sup, _, _ := capturingSupervisor(t)
	sup.StopModule("unknown") // no-op

	gated := func(version string) Spec {
		mf := testManifest("no.such.capability")
		mf.Version = version
		return Spec{Manifest: mf, BinPath: "unused"}
	}
	if err := sup.Add(gated("1.0.0")); err != nil {
		t.Fatal(err)
	}
	if err := sup.Replace(gated("2.0.0")); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	sts := sup.Statuses()
	if len(sts) != 1 || sts[0].Version != "2.0.0" {
		t.Fatalf("after Replace: %+v", sts)
	}
	sup.StopModule("testmod")
	if len(sup.Statuses()) != 0 {
		t.Fatal("StopModule left the module registered")
	}
}

// Each way a module can fail between exec and Start is a launch failure:
// logged with its cause, then backoff — never a running module.
func TestLaunchFailures(t *testing.T) {
	raw := fixture(t, "rawmodule")
	cases := []struct {
		mode string
		want string
	}{
		{"exit", "module exited before handshake"},
		{"hang", "timeout waiting for handshake line"},
		{"garbage", "malformed line"},
		{"flood", `malformed line \"\"`},
		{"wrong-protocol", "outside window"},
		{"nobody-home", "init:"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			t.Setenv("RAWMOD_MODE", c.mode)
			sup, logs, _ := capturingSupervisor(t)
			sup.LaunchTimeout = 500 * time.Millisecond
			if err := sup.Add(Spec{Manifest: testManifest(), BinPath: raw}); err != nil {
				t.Fatal(err)
			}
			waitLog(t, logs, c.want, 20*time.Second)
			if st := sup.Statuses()[0]; st.State == StateRunning {
				t.Fatalf("a module that failed its launch is running: %+v", st)
			}
		})
	}
}

func TestLaunchExecFailure(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	if err := sup.Add(
		Spec{Manifest: testManifest(), BinPath: filepath.Join(t.TempDir(), "absent"+exeSuffix())},
	); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "exec:", 10*time.Second)
}

// Core stopping while a launch is still waiting on the handshake ends the
// launch and leaves the module stopped, not in backoff.
func TestShutdownDuringLaunch(t *testing.T) {
	t.Setenv("RAWMOD_MODE", "hang")
	sup, _, cancel := capturingSupervisor(t)
	sup.LaunchTimeout = time.Minute
	if err := sup.Add(
		Spec{Manifest: testManifest(), BinPath: fixture(t, "rawmodule")},
	); err != nil {
		t.Fatal(err)
	}
	waitState(t, sup, StateStarting, 10*time.Second)
	time.Sleep(200 * time.Millisecond) // let launch reach the handshake wait
	cancel()
	sup.Wait()
	if st := sup.Statuses()[0]; st.State != StateStopped || st.Detail != "core shutting down" {
		t.Fatalf("state after shutdown mid-launch = %s (%s)", st.State, st.Detail)
	}
}

// A module that asks at Init for a capability its manifest did not declare
// is refused, even though the manifest gate let it launch.
func TestRuntimeRequirementsUnmet(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	sup.Caps = capability.Set{}
	if err := sup.Add(
		Spec{Manifest: testManifest(), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "runtime requirements unmet", 20*time.Second)
}

func TestStartRefused(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	if err := sup.Add(Spec{
		Manifest: testManifest("platform.osinfo"), BinPath: fixture(t, "testmodule"),
		Config: []byte(`{"fail_start":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "start:", 20*time.Second)
}

// Degraded is first-class: reported, never a strike.
func TestDegradedModuleKeepsRunning(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	sup.HealthStrikes = 1
	if err := sup.Add(Spec{
		Manifest: testManifest("platform.osinfo"), BinPath: fixture(t, "testmodule"),
		Config: []byte(`{"health":"degraded","stdout":"chatter after the handshake"}`),
	}); err != nil {
		t.Fatal(err)
	}
	st := waitFor(t, sup, "running and degraded", 20*time.Second, func(s Status) bool {
		return s.State == StateRunning && s.Health.GetStatus() == agentv1.Health_STATUS_DEGRADED
	})
	waitLog(t, logs, "module degraded", 5*time.Second)
	time.Sleep(400 * time.Millisecond) // several polls
	if final := sup.Statuses()[0]; final.Restarts != 0 || final.PID != st.PID {
		t.Fatalf("degraded module was restarted: %+v", final)
	}
}

func TestUnhealthyModuleIsRestarted(t *testing.T) {
	for _, strikes := range []int{1, 2} {
		t.Run(fmt.Sprintf("strikes=%d", strikes), func(t *testing.T) {
			sup, logs, _ := capturingSupervisor(t)
			sup.HealthStrikes = strikes
			sup.StartLimitBurst = 100
			if err := sup.Add(Spec{
				Manifest: testManifest("platform.osinfo"), BinPath: fixture(t, "testmodule"),
				Config: []byte(`{"health":"unhealthy"}`),
			}); err != nil {
				t.Fatal(err)
			}
			waitFor(
				t,
				sup,
				"a health-forced restart",
				20*time.Second,
				func(s Status) bool { return s.Restarts >= 1 },
			)
			waitLog(t, logs, "module unhealthy", 5*time.Second)
		})
	}
}

// A failed Stop RPC is logged and shutdown still completes.
func TestStopRPCFailureStillStops(t *testing.T) {
	sup, logs, cancel := capturingSupervisor(t)
	if err := sup.Add(Spec{
		Manifest: testManifest("platform.osinfo"), BinPath: fixture(t, "testmodule"),
		Config: []byte(`{"fail_stop":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	waitState(t, sup, StateRunning, 20*time.Second)
	cancel()
	sup.Wait()
	if !strings.Contains(logs.String(), "module stop failed") {
		t.Fatalf("stop failure not logged:\n%s", logs)
	}
	if st := sup.Statuses()[0]; st.State != StateStopped {
		t.Fatalf("state = %s, want stopped", st.State)
	}
}

// A module that outlives StableAfter before crashing has its crash history
// forgiven, so a slow crash never reaches the start limit.
func TestStableRunResetsCrashCount(t *testing.T) {
	sup, _, _ := capturingSupervisor(t)
	sup.StableAfter = time.Nanosecond
	sup.StartLimitBurst = 2
	if err := sup.Add(Spec{
		Manifest: testManifest("platform.osinfo"), BinPath: fixture(t, "testmodule"),
		Config: []byte(`{"crash_after_ms":100}`),
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(
		t,
		sup,
		"three restarts",
		30*time.Second,
		func(s Status) bool { return s.Restarts >= 3 },
	)
	if st := sup.Statuses()[0]; st.State == StateStartLimited {
		t.Fatal("stable runs still tripped the start limit")
	}
}
