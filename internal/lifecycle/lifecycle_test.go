package lifecycle

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// makeInstallDir builds an installable local module directory at version,
// optionally with a crash-inducing config.
func makeInstallDir(t *testing.T, bin, version string, crashMS int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pkg-"+version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(bin) //nolint:errcheck
	if err := os.WriteFile(filepath.Join(dir, "testmod"+exeSuffix()), data, 0o755); err != nil {
		t.Fatal(err)
	}
	m := manifest.Manifest{
		Schema: 1, ID: "testmod", Version: version, Protocol: 1,
		Zone: "A", Privilege: manifest.PrivilegeService, Session: manifest.SessionSystem,
		Platforms:    []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Capabilities: []string{"platform.osinfo"},
	}
	mb, _ := json.Marshal(m) //nolint:errcheck
	if err := os.WriteFile(filepath.Join(dir, "module.manifest.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	if crashMS > 0 {
		cfg := []byte(`{"crash_after_ms": ` + jsonInt(crashMS) + `}`)
		if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func jsonInt(v int) string {
	b, _ := json.Marshal(v) //nolint:errcheck
	return string(b)
}

// exeSuffix: Windows cannot exec a binary without its extension.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// newTestManager builds the test module and a supervisor+manager pair
// against a fresh short-path state dir. It returns the module binary path.
func newTestManager(t *testing.T) (*Manager, *supervise.Supervisor, string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "testmod"+exeSuffix())
	build := exec.Command("go", "build", "-o", bin, "../supervise/testdata/testmodule")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dir, err := os.MkdirTemp("", "wvlc-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lay := layout.Resolve(dir)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}

	sup := &supervise.Supervisor{
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
		Layout: lay,
		Verifier: supervise.VerifierFunc(
			func(string, *manifest.Manifest) error { return nil },
		),
		Backoff: retry.Backoff{
			Initial: 20 * time.Millisecond,
			Max:     50 * time.Millisecond,
			Factor:  2,
		},
		StartLimitBurst:  3,
		StartLimitWindow: time.Minute,
		HealthInterval:   200 * time.Millisecond,
		StableAfter:      time.Hour,
	}
	mgr := &Manager{
		Log:         log,
		Layout:      lay,
		Verifier:    sup.Verifier,
		Supervisor:  sup,
		GateTimeout: 20 * time.Second,
		GateStable:  1 * time.Second,
	}
	return mgr, sup, bin
}

// TestInstallSurvivesRPCContextCancel is the regression test for the #1
// bug: install/rollback threaded the per-RPC context into the runner's
// lifetime, so the module died the instant the RPC returned. The module
// must stay running after the install context is cancelled.
func TestInstallSurvivesRPCContextCancel(t *testing.T) {
	mgr, sup, bin := newTestManager(t)
	sup.SetBaseContext(context.Background())

	// The install arrives on a short-lived "RPC" context.
	rpcCtx, rpcCancel := context.WithCancel(context.Background())
	if _, err := mgr.InstallLocal(rpcCtx, makeInstallDir(t, bin, "1.0.0", 0)); err != nil {
		t.Fatalf("install: %v", err)
	}
	rpcCancel() // the RPC returns; its context is cancelled.

	// The module must still be running well after the RPC context died.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sts := sup.Statuses()
		if len(sts) == 1 && sts[0].State == supervise.StateRunning {
			time.Sleep(1 * time.Second) // and stay running
			if s := sup.Statuses(); len(s) == 1 && s[0].State == supervise.StateRunning {
				sup.StopModule("testmod")
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("module not running after install RPC context cancelled: %+v", sup.Statuses())
}

func TestInstallHotSwapAndAutoRollback(t *testing.T) {
	mgr, sup, bin := newTestManager(t)
	lay := mgr.Layout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	// 1. Install v1: module comes up.
	v, err := mgr.InstallLocal(ctx, makeInstallDir(t, bin, "1.0.0", 0))
	if err != nil {
		t.Fatalf("install v1: %v", err)
	}
	if v != "1.0.0" {
		t.Fatalf("installed %s, want 1.0.0", v)
	}
	assertRunningVersion(t, sup, "1.0.0")

	// 2. Hot swap to v2.
	if _, err := mgr.InstallLocal(ctx, makeInstallDir(t, bin, "2.0.0", 0)); err != nil {
		t.Fatalf("install v2: %v", err)
	}
	assertRunningVersion(t, sup, "2.0.0")
	if cur := readTrim(t, filepath.Join(lay.ModulesDir, "testmod", "current")); cur != "2.0.0" {
		t.Fatalf("current = %s", cur)
	}
	if prev := readTrim(t, filepath.Join(lay.ModulesDir, "testmod", "previous")); prev != "1.0.0" {
		t.Fatalf("previous = %s", prev)
	}

	// 3. v3 crashes after start: the health gate must fail and the
	// manager must roll back to v2 automatically.
	if _, err := mgr.InstallLocal(ctx, makeInstallDir(t, bin, "3.0.0", 60)); err == nil {
		t.Fatal("broken v3 install reported success")
	}
	assertRunningVersion(t, sup, "2.0.0")
	if cur := readTrim(t, filepath.Join(lay.ModulesDir, "testmod", "current")); cur != "2.0.0" {
		t.Fatalf("current after auto-rollback = %s", cur)
	}

	// 4. Operator rollback flips to the retained previous (1.0.0).
	back, err := mgr.Rollback(ctx, "testmod")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if back != "1.0.0" {
		t.Fatalf("rolled back to %s", back)
	}
	assertRunningVersion(t, sup, "1.0.0")

	sup.StopModule("testmod")
}

func assertRunningVersion(t *testing.T, sup *supervise.Supervisor, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last supervise.Status
	for time.Now().Before(deadline) {
		for _, st := range sup.Statuses() {
			last = st
			if st.State == supervise.StateRunning && st.Version == want {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("never saw %s running; last: %+v", want, last)
}

func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[:len(b)-1])
}
