package core

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/lifecycle"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// The fixture module answers only to the id "testmod", so the one module
// these tests really launch is testmod; others are gated on a capability no
// host has, which the supervisor registers without exec'ing anything.
const fixtureID = "testmod"

var (
	fixtureOnce sync.Once
	fixtureDir  string
	fixtureErr  error
	fixtureOut  []byte
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureDir != "" {
		os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

// fixture builds internal/supervise's test module once per package run.
func fixture(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(func() {
		fixtureDir, fixtureErr = os.MkdirTemp("", "wvfix-*")
		if fixtureErr != nil {
			return
		}
		build := exec.Command("go", "build", "-o", filepath.Join(fixtureDir, exe(fixtureID)),
			"../supervise/testdata/testmodule")
		build.Env = append(build.Environ(), "CGO_ENABLED=0")
		fixtureOut, fixtureErr = build.CombinedOutput()
	})
	if fixtureErr != nil {
		t.Fatalf("building the fixture module: %v\n%s", fixtureErr, fixtureOut)
	}
	return filepath.Join(fixtureDir, exe(fixtureID))
}

type harness struct {
	rec  *reconciler
	sup  *supervise.Supervisor
	lay  layout.Layout
	dir  string
	logs *recorder
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := stateDir(t)
	lay := layout.Resolve(root)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}
	logs := &recorder{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	sup := &supervise.Supervisor{
		Log:    log,
		Window: Window,
		Caps:   baseCaps(),
		Services: &hostserv.Services{
			Log: log, Bus: eventbus.New(),
			Store: hostserv.NewMemStore(), Policy: hostserv.NewMemPolicy(),
			Identity: hostserv.NewStubIdentity(), Transport: &hostserv.LogTransport{Log: log},
		},
		Layout:   lay,
		Verifier: supervise.VerifierFunc(func(string, *manifest.Manifest) error { return nil }),
		Backoff: retry.Backoff{
			Initial: 20 * time.Millisecond, Max: 50 * time.Millisecond, Factor: 2,
		},
		StartLimitBurst:  3,
		StartLimitWindow: time.Minute,
		HealthInterval:   100 * time.Millisecond,
		LaunchTimeout:    15 * time.Second,
		StableAfter:      time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	sup.SetBaseContext(ctx)
	t.Cleanup(func() {
		cancel()
		sup.Wait()
	})
	return &harness{
		rec:  &reconciler{log: log, dir: lay.ModulesDir, sup: sup},
		sup:  sup,
		lay:  lay,
		dir:  lay.ModulesDir,
		logs: logs,
	}
}

// install lays a flat module down the way a module package does.
func (h *harness) install(t *testing.T, id, version, config string, caps ...string) {
	t.Helper()
	dir := filepath.Join(h.dir, id)
	m := testManifest(id, caps...)
	m.Version = version
	writeManifest(t, dir, m)
	if id == fixtureID {
		copyFile(t, fixture(t), filepath.Join(dir, exe(id)))
	} else {
		writeFile(t, filepath.Join(dir, exe(id)), "gated "+version)
	}
	if config != "" {
		writeFile(t, filepath.Join(dir, "config.json"), config)
	}
}

// copyFile writes dst beside itself and renames it into place, as dpkg
// does: Linux refuses to open a running binary for writing.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dst+".tmp", string(b))
	if err := os.Rename(dst+".tmp", dst); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) reconcile(t *testing.T) Diff {
	t.Helper()
	d, err := h.rec.reconcile()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return d
}

func (h *harness) status(id string) (registry.Module, bool) {
	return h.sup.Modules().Get(id)
}

func (h *harness) waitFor(
	t *testing.T,
	id, desc string,
	pred func(registry.Module) bool,
) registry.Module {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last registry.Module
	for time.Now().Before(deadline) {
		if m, ok := h.status(id); ok {
			last = m
			if pred(m) {
				return m
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never %s; last %+v", id, desc, last)
	return registry.Module{}
}

func (h *harness) waitRunning(t *testing.T, id, version string) registry.Module {
	t.Helper()
	return h.waitFor(t, id, "ran "+version, func(m registry.Module) bool {
		return m.State == registry.StateRunning && m.Version == version && m.PID > 0
	})
}

func wantDiff(t *testing.T, got Diff, added, removed, replaced []string) {
	t.Helper()
	if !slices.Equal(got.Added, added) || !slices.Equal(got.Removed, removed) ||
		!slices.Equal(got.Replaced, replaced) {
		t.Fatalf("diff = %+v, want added %v removed %v replaced %v", got, added, removed, replaced)
	}
}

// A module package installed and removed while core runs: the module starts,
// then stops and leaves the registry, with no restart of anything else.
func TestReconcileAddAndRemove(t *testing.T) {
	h := newHarness(t)
	wantDiff(t, h.reconcile(t), nil, nil, nil)

	h.install(t, fixtureID, "1.0.0", "", "platform.osinfo")
	h.install(t, "bystander", "1.0.0", "", "never.present")
	wantDiff(t, h.reconcile(t), []string{"bystander", fixtureID}, nil, nil)
	h.waitRunning(t, fixtureID, "1.0.0")
	by, _ := h.status("bystander")

	// Nothing changed: nothing happens.
	wantDiff(t, h.reconcile(t), nil, nil, nil)

	if err := os.RemoveAll(filepath.Join(h.dir, fixtureID)); err != nil {
		t.Fatal(err)
	}
	wantDiff(t, h.reconcile(t), nil, []string{fixtureID}, nil)
	if m, ok := h.status(fixtureID); ok {
		t.Fatalf("removed module still registered: %+v", m)
	}
	if again, _ := h.status("bystander"); !again.Since.Equal(by.Since) {
		t.Fatal("removing one module disturbed another")
	}
}

// A new manifest version replaces the running process.
func TestReconcileVersionChange(t *testing.T) {
	h := newHarness(t)
	h.install(t, fixtureID, "1.0.0", "", "platform.osinfo")
	h.reconcile(t)
	before := h.waitRunning(t, fixtureID, "1.0.0")

	h.install(t, fixtureID, "1.1.0", "", "platform.osinfo")
	wantDiff(t, h.reconcile(t), nil, nil, []string{fixtureID})
	after := h.waitRunning(t, fixtureID, "1.1.0")
	if after.PID == before.PID {
		t.Fatal("replaced module kept its process")
	}
}

// A changed config.json reaches the module: it is replaced, and the new
// process runs with the new document.
func TestReconcileConfigChange(t *testing.T) {
	h := newHarness(t)
	h.install(t, fixtureID, "1.0.0", `{}`, "platform.osinfo")
	h.reconcile(t)
	h.waitRunning(t, fixtureID, "1.0.0")

	writeFile(t, filepath.Join(h.dir, fixtureID, "config.json"), `{"health":"degraded"}`)
	wantDiff(t, h.reconcile(t), nil, nil, []string{fixtureID})
	h.waitFor(t, fixtureID, "reported degraded", func(m registry.Module) bool {
		return m.State == registry.StateRunning &&
			m.Health.GetStatus() == agentv1.Health_STATUS_DEGRADED
	})
}

// A binary rewritten in place at the same version is a different module.
func TestReconcileBinaryChange(t *testing.T) {
	h := newHarness(t)
	h.install(t, "gated", "1.0.0", "", "never.present")
	h.reconcile(t)
	writeFile(t, filepath.Join(h.dir, "gated", exe("gated")), "rebuilt")
	wantDiff(t, h.reconcile(t), nil, nil, []string{"gated"})
	want, err := supervise.FileDigest(filepath.Join(h.dir, "gated", exe("gated")))
	if err != nil {
		t.Fatal(err)
	}
	if spec := h.sup.Specs()["gated"]; spec.Digest != want {
		t.Fatalf("running digest %s, want %s", spec.Digest, want)
	}
}

// One bad module directory is recorded invalid and every other module
// carries on; fixed, it starts.
func TestReconcileInvalidModule(t *testing.T) {
	h := newHarness(t)
	h.install(t, fixtureID, "1.0.0", "", "platform.osinfo")
	h.install(t, "bystander", "1.0.0", "", "never.present")
	writeFile(
		t,
		filepath.Join(h.dir, "nobin", "module.manifest.json"),
		mustJSON(t, testManifest("nobin")),
	)
	d := h.reconcile(t)
	wantDiff(t, d, []string{"bystander", fixtureID}, nil, nil)
	if len(d.Invalid) != 1 || d.Invalid[0].ID != "nobin" {
		t.Fatalf("invalid = %+v", d.Invalid)
	}
	h.waitRunning(t, fixtureID, "1.0.0")
	if m, _ := h.status("nobin"); m.State != registry.StateInvalid || m.Detail == "" {
		t.Fatalf("nobin = %+v", m)
	}
	by, _ := h.status("bystander")

	// The running module's manifest is corrupted: it stops and is invalid.
	writeFile(t, filepath.Join(h.dir, fixtureID, "module.manifest.json"), "{")
	d = h.reconcile(t)
	wantDiff(t, d, nil, nil, nil)
	if len(d.Invalid) != 2 {
		t.Fatalf("invalid = %+v", d.Invalid)
	}
	m, _ := h.status(fixtureID)
	if m.State != registry.StateInvalid || h.sup.Specs()[fixtureID].Manifest != nil {
		t.Fatalf(
			"corrupt module = %+v, still supervised: %v",
			m,
			h.sup.Specs()[fixtureID].Manifest != nil,
		)
	}
	// Found again with the same fault: the entry is not re-stamped.
	h.reconcile(t)
	if again, _ := h.status(fixtureID); !again.Since.Equal(m.Since) {
		t.Fatal("an unchanged fault moved the invalid entry's since")
	}
	if again, _ := h.status("bystander"); !again.Since.Equal(by.Since) {
		t.Fatal("an invalid module disturbed another")
	}

	// Fixed: it starts. Removed: its invalid entry goes.
	h.install(t, fixtureID, "1.0.0", "", "platform.osinfo")
	wantDiff(t, h.reconcile(t), []string{fixtureID}, nil, nil)
	h.waitRunning(t, fixtureID, "1.0.0")
	if err := os.RemoveAll(filepath.Join(h.dir, "nobin")); err != nil {
		t.Fatal(err)
	}
	if d := h.reconcile(t); len(d.Invalid) != 0 {
		t.Fatalf("invalid = %+v", d.Invalid)
	}
	if _, ok := h.status("nobin"); ok {
		t.Fatal("a removed invalid module is still listed")
	}
}

// A module the supervisor refuses is invalid with the supervisor's reason.
func TestReconcileAddRefused(t *testing.T) {
	h := newHarness(t)
	a := testManifest("a", "never.present")
	a.Address = "weave.same"
	b := testManifest("b", "never.present")
	b.Address = "weave.same"
	for _, m := range []manifest.Manifest{a, b} {
		writeManifest(t, filepath.Join(h.dir, m.ID), m)
		writeFile(t, filepath.Join(h.dir, m.ID, exe(m.ID)), m.ID)
	}
	d := h.reconcile(t)
	wantDiff(t, d, []string{"a"}, nil, nil)
	if len(d.Invalid) != 1 || d.Invalid[0].ID != "b" {
		t.Fatalf("invalid = %+v", d.Invalid)
	}

	// b changed but its address is still a's: still refused, still invalid.
	writeFile(t, filepath.Join(h.dir, "b", exe("b")), "b2")
	if d := h.reconcile(t); len(d.Invalid) != 1 {
		t.Fatalf("invalid = %+v", d.Invalid)
	}
}

// The lifecycle manager's layout: flipping `current` replaces the module
// with the version it names.
func TestReconcileVersionedLayout(t *testing.T) {
	h := newHarness(t)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		dir := filepath.Join(h.dir, fixtureID, "versions", v)
		m := testManifest(fixtureID, "platform.osinfo")
		m.Version = v
		writeManifest(t, dir, m)
		copyFile(t, fixture(t), filepath.Join(dir, exe(fixtureID)))
	}
	writeFile(t, filepath.Join(h.dir, fixtureID, "current"), "1.0.0\n")
	wantDiff(t, h.reconcile(t), []string{fixtureID}, nil, nil)
	h.waitRunning(t, fixtureID, "1.0.0")

	writeFile(t, filepath.Join(h.dir, fixtureID, "current"), "2.0.0\n")
	wantDiff(t, h.reconcile(t), nil, nil, []string{fixtureID})
	h.waitRunning(t, fixtureID, "2.0.0")
	if bin := h.sup.Specs()[fixtureID].BinPath; filepath.Base(filepath.Dir(bin)) != "2.0.0" {
		t.Fatalf("running %s", bin)
	}
}

// A module built for another host is skipped, said once, and stopped if it
// was running.
func TestReconcileUnsupportedHost(t *testing.T) {
	h := newHarness(t)
	h.install(t, "m", "1.0.0", "", "never.present")
	h.reconcile(t)
	m := testManifest("m", "never.present")
	m.Platforms = []manifest.Platform{{OS: otherOS(), Arch: "amd64"}}
	writeManifest(t, filepath.Join(h.dir, "m"), m)
	wantDiff(t, h.reconcile(t), nil, []string{"m"}, nil)
	h.reconcile(t)
	n := 0
	h.logs.mu.Lock()
	for _, l := range h.logs.lines {
		if strings.Contains(l, "does not support this host") {
			n++
		}
	}
	h.logs.mu.Unlock()
	if n != 1 {
		t.Fatalf("logged %d times", n)
	}
	if err := os.RemoveAll(filepath.Join(h.dir, "m")); err != nil {
		t.Fatal(err)
	}
	wantDiff(t, h.reconcile(t), nil, nil, nil)
	if h.rec.skipped["m"] {
		t.Fatal("a removed module is still remembered as skipped")
	}
}

// A binary caught mid-write is left alone and looked at again.
func TestReconcileUnsettledRetries(t *testing.T) {
	h := newHarness(t)
	var d Diff
	m := testManifest("m")
	if !h.rec.apply(
		"m",
		moduleEntry{spec: supervise.Spec{Manifest: &m}, unsettled: true},
		true,
		&d,
	) {
		t.Fatal("unsettled binary not retried")
	}
	if len(h.sup.Specs()) != 0 {
		t.Fatal("an unsettled module was registered")
	}
	select {
	case <-h.rec.triggers():
		t.Fatal("apply triggered by itself")
	default:
	}
}

// A modules directory that cannot be read changes nothing.
func TestReconcileUnreadableDirChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.install(t, "m", "1.0.0", "", "never.present")
	h.reconcile(t)
	h.rec.dir = filepath.Join(h.dir, "bad\x00dir")
	if _, err := h.rec.reconcile(); err == nil {
		t.Fatal("reconciled an unreadable directory")
	}
	h.rec.pass()
	if !h.logs.has("module reload failed") {
		t.Fatal("failed pass not logged")
	}
	if _, ok := h.sup.Specs()["m"]; !ok {
		t.Fatal("an unreadable directory stopped a module")
	}
}

// A reload and a lifecycle install of the same module take turns. The
// install replaces the process before it flips `current`; a reload that
// looked in between would see the old version on disk and put it back.
func TestReconcileRacesLifecycleInstall(t *testing.T) {
	h := newHarness(t)
	lay := h.lay
	mgr := &lifecycle.Manager{
		Log: h.rec.log, Layout: lay, Verifier: h.sup.Verifier, Supervisor: h.sup,
		GateTimeout: 20 * time.Second, GateStable: 500 * time.Millisecond,
	}
	h.rec.lock = mgr
	pkg := func(version string) string {
		dir := filepath.Join(t.TempDir(), version)
		m := testManifest(fixtureID, "platform.osinfo")
		m.Version = version
		writeManifest(t, dir, m)
		copyFile(t, fixture(t), filepath.Join(dir, exe(fixtureID)))
		return dir
	}
	if _, err := mgr.InstallLocal(context.Background(), pkg("1.0.0")); err != nil {
		t.Fatal(err)
	}
	// Installed by lifecycle and already supervised: a reload agrees.
	wantDiff(t, h.reconcile(t), nil, nil, nil)

	stop := make(chan struct{})
	var replaced atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d, err := h.rec.reconcile()
			if err != nil {
				t.Error(err)
				return
			}
			replaced.Add(int32(len(d.Replaced) + len(d.Added) + len(d.Removed)))
			time.Sleep(5 * time.Millisecond)
		}
	}()
	_, err := mgr.InstallLocal(context.Background(), pkg("2.0.0"))
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("install raced by reloads: %v", err)
	}
	if n := replaced.Load(); n != 0 {
		t.Fatalf("reloads acted %d times on a module an install held", n)
	}
	h.waitRunning(t, fixtureID, "2.0.0")
	wantDiff(t, h.reconcile(t), nil, nil, nil)
}

// A burst of triggers is one pass, after the quiet period.
func TestReconcileDebounce(t *testing.T) {
	h := newHarness(t)
	var passes atomic.Int32
	h.rec.debounce = 50 * time.Millisecond
	h.rec.afterPass = func() { passes.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.rec.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	for range 20 {
		h.rec.trigger()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	if n := passes.Load(); n != 1 {
		t.Fatalf("%d passes for one burst", n)
	}

	// A stream that never goes quiet still gets a pass by the ceiling.
	passes.Store(0)
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.rec.trigger()
		time.Sleep(10 * time.Millisecond)
	}
	if passes.Load() == 0 {
		t.Fatal("a continuous stream of triggers starved the reload")
	}
}

// The periodic rescan finds what nothing reported.
func TestReconcilePeriodicRescan(t *testing.T) {
	h := newHarness(t)
	h.rec.rescan = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.rec.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	h.install(t, "m", "1.0.0", "", "never.present")
	h.waitFor(t, "m", "registered", func(registry.Module) bool { return true })
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
