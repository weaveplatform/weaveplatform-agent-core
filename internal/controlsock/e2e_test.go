package controlsock

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/lifecycle"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// stubIdentity satisfies the control server's Identity dependency for Status.
type stubIdentity struct{}

func (stubIdentity) WhoAmI(
	context.Context,
) (string, bool, string) {
	return "test-device", true, ""
}
func (stubIdentity) Enrolled() bool { return false }

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// installDir builds an installable local module directory at version.
func installDir(t *testing.T, bin, version string) string {
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
	return dir
}

// TestControlPlaneInstallOutlivesRPC is the permanent e2e lock for the #1
// bug: an Install driven over the real control socket must leave the module
// running well after the install RPC (and its context) has returned. If the
// per-RPC context ever leaks back into the runner's lifetime, the module
// dies when the call ends and this fails.
func TestControlPlaneInstallOutlivesRPC(t *testing.T) {
	// Build the test module.
	bin := filepath.Join(t.TempDir(), "testmod"+exeSuffix())
	build := exec.Command("go", "build", "-o", bin, "../supervise/testdata/testmodule")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// Short path: macOS unix sockets cap sun_path at 104 bytes.
	dir, err := os.MkdirTemp("", "wvctl-*")
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
			Log: log, Bus: eventbus.New(),
			Store: hostserv.NewMemStore(), Policy: hostserv.NewMemPolicy(),
			Identity: hostserv.NewStubIdentity(), Transport: &hostserv.LogTransport{Log: log},
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
	// The run-lifetime context: modules live and die with THIS, not with the
	// per-RPC context of the install call.
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	sup.SetBaseContext(runCtx)

	mgr := &lifecycle.Manager{
		Log: log, Layout: lay, Verifier: sup.Verifier, Supervisor: sup,
		GateTimeout: 20 * time.Second, GateStable: 500 * time.Millisecond,
	}

	srv := &Server{
		Log: log, Supervisor: sup, Lifecycle: mgr,
		Window: handshake.Window{Min: 1, Max: 1}, Identity: stubIdentity{}, StartedAt: time.Now(),
	}
	go srv.Serve(runCtx, controlAddr(lay)) //nolint:errcheck
	t.Cleanup(func() {
		if srv.grpcServer != nil {
			srv.grpcServer.Stop()
		}
	})

	// Dial the control socket like weavectl does, and Install with a context
	// we cancel the instant the call returns.
	client, conn, err := dialWithRetry(t, controlAddr(lay))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ictx, icancel := context.WithTimeout(context.Background(), 30*time.Second)
	resp, err := client.Install(
		ictx,
		&controlv1.InstallRequest{LocalPath: installDir(t, bin, "1.0.0")},
	)
	icancel() // the install RPC context is now dead
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if resp.GetInstalledVersion() != "1.0.0" {
		t.Fatalf("installed %s, want 1.0.0", resp.GetInstalledVersion())
	}

	// The module must still be running seconds after the RPC context died.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		mres, err := client.Modules(context.Background(), &controlv1.ModulesRequest{})
		if err != nil {
			t.Fatalf("modules: %v", err)
		}
		if !oneModuleRunning(mres) {
			t.Fatalf("module not running %v after install RPC returned: %+v",
				time.Until(deadline), mres.GetModules())
		}
	}
}

func oneModuleRunning(res *controlv1.ModulesResponse) bool {
	for _, m := range res.GetModules() {
		// State may carry a ": detail" suffix; match the base state.
		if m.GetId() == "testmod" && strings.HasPrefix(m.GetState(), "running") {
			return true
		}
	}
	return false
}

func dialWithRetry(
	t *testing.T,
	addr string,
) (controlv1.ControlServiceClient, interface{ Close() error }, error) {
	t.Helper()
	var lastErr error
	for i := 0; i < 50; i++ {
		client, conn, err := Dial(addr)
		if err == nil {
			return client, conn, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, nil, lastErr
}
