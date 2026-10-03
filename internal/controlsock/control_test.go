package controlsock

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	"github.com/weaveplatform/weaveplatform-agent-core/internal/version"
)

// controlAddr is the layout's control socket on unix. On Windows the
// layout's pipe name is fixed machine-wide, and packages test in parallel,
// so each test takes its own pipe instead.
func controlAddr(lay layout.Layout) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\weave-control-test-` + filepath.Base(lay.StateDir)
	}
	return lay.ControlSocket()
}

func buildModule(t *testing.T, pkg, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name+exeSuffix())
	build := exec.Command("go", "build", "-o", bin, pkg)
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

type harness struct {
	sup    *supervise.Supervisor
	lay    layout.Layout
	client controlv1.ControlServiceClient
}

func startControl(t *testing.T) harness {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir, err := os.MkdirTemp("", "wvc-*")
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
	runCtx, runCancel := context.WithCancel(context.Background())
	sup.SetBaseContext(runCtx)
	mgr := &lifecycle.Manager{
		Log: log, Layout: lay, Verifier: sup.Verifier, Supervisor: sup,
		GateTimeout: 20 * time.Second, GateStable: 300 * time.Millisecond,
	}
	srv := &Server{
		Log: log, Supervisor: sup, Lifecycle: mgr,
		Window: handshake.Window{Min: 1, Max: 1}, Identity: stubIdentity{}, StartedAt: time.Now(),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(runCtx, controlAddr(lay)) }()
	t.Cleanup(func() {
		runCancel()
		<-served
		sup.Wait()
	})
	client, conn, err := dialWithRetry(t, controlAddr(lay))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	// The client connects lazily; wait until the server actually answers so
	// no test's first RPC races the listener.
	eventually(t, "the control service", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := client.Status(ctx, &controlv1.StatusRequest{})
		return err == nil
	})
	return harness{sup: sup, lay: lay, client: client}
}

func spec(t *testing.T, bin, id string, caps ...string) supervise.Spec {
	t.Helper()
	return supervise.Spec{
		BinPath: bin,
		Manifest: &manifest.Manifest{
			Schema: 1, ID: id, Version: "1.0.0", Protocol: 1,
			Zone: "A", Privilege: manifest.PrivilegeService, Session: manifest.SessionSystem,
			Platforms:    []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
			Capabilities: caps,
		},
	}
}

func eventually(t *testing.T, what string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !pred() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The read side of the control surface: status, module states with their
// detail, and the surfaces a running module declared — what weavectl and
// the portal show an operator.
func TestControlReadPaths(t *testing.T) {
	// Built before startControl so its directory is cleaned up after the
	// supervisor has stopped the module: cleanups run last-registered first,
	// and Windows will not delete a running executable.
	bin := buildModule(t, "./testdata/surfacemod", "surfmod")
	h := startControl(t)
	ctx := context.Background()
	if err := h.sup.Add(spec(t, bin, "surfmod", "platform.osinfo")); err != nil {
		t.Fatal(err)
	}
	if err := h.sup.Add(spec(t, bin, "gated", "never.present")); err != nil {
		t.Fatal(err)
	}

	st, err := h.client.Status(ctx, &controlv1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetCoreVersion() != version.Version || st.GetDeviceId() != "test-device" ||
		st.GetEnrolled() ||
		st.GetProtocol().GetMin() != 1 ||
		st.GetProtocol().GetMax() != 1 {
		t.Fatalf("Status = %v", st)
	}

	var surfaces *controlv1.SurfacesResponse
	eventually(t, "surfmod's surface", func() bool {
		surfaces, err = h.client.Surfaces(ctx, &controlv1.SurfacesRequest{})
		return err == nil && len(surfaces.GetModules()) == 1
	})
	// The gated module never ran, so it declared nothing and is omitted.
	if m := surfaces.GetModules()[0]; m.GetModuleId() != "surfmod" ||
		m.GetSurfaces()[0].GetId() != "panel" {
		t.Fatalf("Surfaces = %v", surfaces)
	}

	mods, err := h.client.Modules(ctx, &controlv1.ModulesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var gated string
	for _, m := range mods.GetModules() {
		if m.GetId() == "gated" {
			gated = m.GetState()
		}
	}
	// The reason a module is not running travels with its state.
	if !strings.Contains(gated, ": ") || !strings.Contains(gated, "never.present") {
		t.Fatalf("gated module state %q carries no detail", gated)
	}
}

func TestControlInstallAndRollback(t *testing.T) {
	bin := buildModule(t, "../supervise/testdata/testmodule", "testmod")
	h := startControl(t)
	ctx := context.Background()

	// Nothing installed yet: no previous version to return to.
	if _, err := h.client.Rollback(
		ctx,
		&controlv1.RollbackRequest{ModuleId: "testmod"},
	); status.Code(
		err,
	) != codes.FailedPrecondition {
		t.Fatalf("Rollback with no history: %v", err)
	}
	// No manifest source is configured, so a channel install must be refused.
	if _, err := h.client.Install(
		ctx,
		&controlv1.InstallRequest{ModuleId: "testmod", Version: "1.0.0"},
	); status.Code(
		err,
	) != codes.FailedPrecondition {
		t.Fatalf("channel install without a manifest source: %v", err)
	}

	for _, v := range []string{"1.0.0", "2.0.0"} {
		resp, err := h.client.Install(
			ctx,
			&controlv1.InstallRequest{LocalPath: installDir(t, bin, v)},
		)
		if err != nil || resp.GetInstalledVersion() != v {
			t.Fatalf("install %s: %v %v", v, resp, err)
		}
	}
	rb, err := h.client.Rollback(ctx, &controlv1.RollbackRequest{ModuleId: "testmod"})
	if err != nil || rb.GetRolledBackTo() != "1.0.0" {
		t.Fatalf("Rollback = %v, %v", rb, err)
	}
}

func TestControlLogsIsUnimplemented(t *testing.T) {
	h := startControl(t)
	stream, err := h.client.Logs(context.Background(), &controlv1.LogsRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Logs = %v", err)
	}
}

func TestServeReportsAListenFailure(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "absent", "control.sock")
	if runtime.GOOS == "windows" {
		addr = filepath.Join(t.TempDir(), "not-a-pipe")
	}
	srv := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := srv.Serve(context.Background(), addr); err == nil {
		t.Fatal("Serve succeeded on an address it cannot listen on")
	}
}

func TestDialRejectsAnUnusableAddress(t *testing.T) {
	if _, _, err := Dial("bad\x00addr"); err == nil {
		t.Fatal("Dial accepted an address with a NUL in it")
	}
}
