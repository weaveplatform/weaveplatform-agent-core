package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

// fakeControl is a ControlService that answers from canned values and
// records what weavectl asked for, so each verb's request and rendering
// can be checked over a real control socket.
type fakeControl struct {
	controlv1.UnimplementedControlServiceServer

	mu       sync.Mutex
	install  *controlv1.InstallRequest
	rollback *controlv1.RollbackRequest
	surfaces *controlv1.SurfacesResponse
	reload   *controlv1.ReloadResponse
	core     *agentv1.CoreCondition
	fail     bool
}

func (f *fakeControl) err() error {
	if f.fail {
		return status.Error(codes.FailedPrecondition, "fake refused")
	}
	return nil
}

func (f *fakeControl) Status(
	context.Context,
	*controlv1.StatusRequest,
) (*controlv1.StatusResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return &controlv1.StatusResponse{
		CoreVersion: "1.2.3", Protocol: &agentv1.ProtocolRange{Min: 1, Max: 2},
		DeviceId: "dev-1", Enrolled: true, UptimeSeconds: 90, Core: f.core,
	}, nil
}

func (f *fakeControl) Modules(
	context.Context,
	*controlv1.ModulesRequest,
) (*controlv1.ModulesResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	return &controlv1.ModulesResponse{Modules: []*controlv1.ModuleStatus{
		{
			Id:       "weave-linux-presence",
			Address:  "weave.presence",
			Version:  "0.1.0",
			Protocol: 1,
			State:    "running",
			Pid:      42,
			Restarts: 1,
			Health:   &agentv1.Health{Status: agentv1.Health_STATUS_DEGRADED, Reason: "slow disk"},
		},
		{Id: "quiet", Version: "0.2.0", Protocol: 1, State: "starting"},
		{
			Id: "fine", Version: "0.3.0", Protocol: 1, State: "running",
			Health: &agentv1.Health{Status: agentv1.Health_STATUS_HEALTHY},
		},
	}}, nil
}

func (f *fakeControl) Surfaces(
	context.Context,
	*controlv1.SurfacesRequest,
) (*controlv1.SurfacesResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.surfaces == nil {
		return &controlv1.SurfacesResponse{}, nil
	}
	return f.surfaces, nil
}

func (f *fakeControl) Install(
	_ context.Context,
	req *controlv1.InstallRequest,
) (*controlv1.InstallResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.install = req
	return &controlv1.InstallResponse{InstalledVersion: "9.9.9"}, nil
}

func (f *fakeControl) Rollback(
	_ context.Context,
	req *controlv1.RollbackRequest,
) (*controlv1.RollbackResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollback = req
	return &controlv1.RollbackResponse{RolledBackTo: "0.0.9"}, nil
}

func (f *fakeControl) Reload(
	context.Context,
	*controlv1.ReloadRequest,
) (*controlv1.ReloadResponse, error) {
	if err := f.err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reload == nil {
		return &controlv1.ReloadResponse{}, nil
	}
	return f.reload, nil
}

func socketAddr(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\weavectl-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	// Short path: macOS unix sockets cap sun_path at 104 bytes.
	dir, err := os.MkdirTemp("", "wctl-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func serve(t *testing.T, f *fakeControl) string {
	t.Helper()
	addr := socketAddr(t)
	lis, err := ipc.Listen(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	controlv1.RegisterControlServiceServer(srv, f)
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return addr
}

func ctl(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestStatus(t *testing.T) {
	addr := serve(t, &fakeControl{})
	code, out, errOut := ctl("-socket", addr, "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"core      1.2.3", "protocol  [1,2]", "device    dev-1", "enrolled  true", "uptime    1m30s"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
}

// A degraded core says so, with the reason and what is disabled; a whole one
// prints no such lines.
func TestStatusDegraded(t *testing.T) {
	addr := serve(t, &fakeControl{core: &agentv1.CoreCondition{
		Degraded: true, Reason: "store sealed elsewhere", Unavailable: []string{"store", "identity"},
	}})
	code, out, errOut := ctl("-socket", addr, "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"DEGRADED  store sealed elsewhere", "disabled  store, identity"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
	_, out, _ = ctl("-socket", serve(t, &fakeControl{}), "status")
	if strings.Contains(out, "DEGRADED") {
		t.Fatalf("a whole core printed degraded:\n%s", out)
	}
}

func TestModules(t *testing.T) {
	addr := serve(t, &fakeControl{})
	code, out, errOut := ctl("-socket", addr, "modules")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "MODULE") {
		t.Fatalf("want header + 3 rows:\n%s", out)
	}
	if !strings.Contains(lines[1], "weave.presence") {
		t.Errorf("row lacks the channel address: %q", lines[1])
	}
	if f := strings.Fields(lines[2]); len(f) < 2 || f[1] != "-" {
		t.Errorf("a module without an address should show '-': %q", lines[2])
	}
	if !strings.Contains(lines[1], "STATUS_DEGRADED (slow disk)") ||
		!strings.Contains(lines[1], "42") {
		t.Errorf("degraded row: %q", lines[1])
	}
	if !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("module without health should show '-': %q", lines[2])
	}
	if !strings.HasSuffix(strings.TrimSpace(lines[3]), "STATUS_HEALTHY") {
		t.Errorf("healthy row carries a reason it does not have: %q", lines[3])
	}
}

func TestSurfaces(t *testing.T) {
	f := &fakeControl{}
	addr := serve(t, f)
	code, out, _ := ctl("-socket", addr, "surfaces")
	if code != 0 || strings.TrimSpace(out) != "no surfaces declared" {
		t.Fatalf("empty surfaces: exit %d %q", code, out)
	}

	f.mu.Lock()
	f.surfaces = &controlv1.SurfacesResponse{Modules: []*controlv1.ModuleSurfaces{
		{
			ModuleId: "weave-linux-presence",
			Surfaces: []*agentv1.Surface{
				{Id: "panel", Kind: "card", Title: "Disk", Data: []byte("abcd")},
			},
		},
	}}
	f.mu.Unlock()
	code, out, _ = ctl("-socket", addr, "surfaces")
	if code != 0 ||
		!strings.Contains(out, `weave-linux-presence/panel  kind=card  title="Disk"  (4 bytes)`) {
		t.Fatalf("surfaces: exit %d %q", code, out)
	}
}

func TestInstall(t *testing.T) {
	f := &fakeControl{}
	addr := serve(t, f)

	code, out, errOut := ctl("-socket", addr, "install", "weave-linux-presence", "0.2.0")
	if code != 0 || strings.TrimSpace(out) != "installed 9.9.9" {
		t.Fatalf("install: exit %d %q %s", code, out, errOut)
	}
	f.mu.Lock()
	if f.install.GetModuleId() != "weave-linux-presence" || f.install.GetVersion() != "0.2.0" ||
		f.install.GetLocalPath() != "" {
		t.Errorf("install request = %v", f.install)
	}
	f.mu.Unlock()

	if code, _, _ := ctl("-socket", addr, "install", "weave-linux-presence"); code != 0 {
		t.Fatalf("install without version: exit %d", code)
	}
	f.mu.Lock()
	if f.install.GetVersion() != "" {
		t.Errorf("version invented: %v", f.install)
	}
	f.mu.Unlock()

	// A relative -local path must reach core absolute: core resolves it
	// from its own working directory, not the operator's.
	if code, _, _ := ctl("-socket", addr, "install", "-local", "pkg"); code != 0 {
		t.Fatalf("install -local: exit %d", code)
	}
	wd, _ := os.Getwd() //nolint:errcheck
	f.mu.Lock()
	if f.install.GetLocalPath() != filepath.Join(wd, "pkg") || f.install.GetModuleId() != "" {
		t.Errorf("local install request = %v", f.install)
	}
	f.mu.Unlock()

	if code, _, errOut := ctl(
		"-socket",
		addr,
		"install",
	); code != 2 ||
		!strings.Contains(errOut, "Usage:") {
		t.Fatalf("bare install: exit %d %q", code, errOut)
	}
}

func TestRollback(t *testing.T) {
	f := &fakeControl{}
	addr := serve(t, f)
	code, out, _ := ctl("-socket", addr, "rollback", "weave-linux-presence")
	if code != 0 || strings.TrimSpace(out) != "rolled back to 0.0.9" {
		t.Fatalf("rollback: exit %d %q", code, out)
	}
	f.mu.Lock()
	if f.rollback.GetModuleId() != "weave-linux-presence" {
		t.Errorf("rollback request = %v", f.rollback)
	}
	f.mu.Unlock()
	if code, _, _ := ctl("-socket", addr, "rollback"); code != 2 {
		t.Fatalf("rollback without module: exit %d", code)
	}
}

func TestReload(t *testing.T) {
	f := &fakeControl{}
	addr := serve(t, f)
	code, out, errOut := ctl("-socket", addr, "reload")
	if code != 0 || strings.TrimSpace(out) != "no module changes" {
		t.Fatalf("empty reload: exit %d %q %s", code, out, errOut)
	}

	f.mu.Lock()
	f.reload = &controlv1.ReloadResponse{
		Added:    []string{"weave-linux-exec"},
		Removed:  []string{"weave-linux-old"},
		Replaced: []string{"weave-linux-presence"},
		Invalid: []*controlv1.InvalidModule{
			{Id: "weave-linux-broken", Detail: "manifest: unexpected end of JSON input"},
		},
	}
	f.mu.Unlock()
	code, out, _ = ctl("-socket", addr, "reload")
	want := "added     weave-linux-exec\n" +
		"removed   weave-linux-old\n" +
		"replaced  weave-linux-presence\n" +
		"invalid   weave-linux-broken  manifest: unexpected end of JSON input\n"
	if code != 0 || out != want {
		t.Fatalf("reload: exit %d\n%s\nwant\n%s", code, out, want)
	}

	// Nothing changed, but something is still broken: both are said.
	f.mu.Lock()
	f.reload = &controlv1.ReloadResponse{
		Invalid: []*controlv1.InvalidModule{{Id: "b", Detail: "no binary"}},
	}
	f.mu.Unlock()
	code, out, _ = ctl("-socket", addr, "reload")
	if code != 0 || out != "invalid  b  no binary\nno module changes\n" {
		t.Fatalf("invalid only: exit %d %q", code, out)
	}
}

func TestServerErrorsExitOne(t *testing.T) {
	addr := serve(t, &fakeControl{fail: true})
	for _, args := range [][]string{
		{"status"}, {"modules"}, {"surfaces"}, {"install", "m"}, {"rollback", "m"}, {"reload"},
	} {
		code, _, errOut := ctl(append([]string{"-socket", addr}, args...)...)
		if code != 1 || !strings.Contains(errOut, "weavectl: "+args[0]+":") ||
			!strings.Contains(errOut, "fake refused") {
			t.Errorf("%v: exit %d %q", args, code, errOut)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, errOut := ctl(); code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no verb: exit %d %q", code, errOut)
	}
	if code, _, _ := ctl("-bogus"); code != 2 {
		t.Fatalf("bad flag: exit %d", code)
	}
	if code, _, _ := ctl("-h"); code != 0 {
		t.Fatalf("-h: exit %d", code)
	}
	addr := serve(t, &fakeControl{})
	if code, _, errOut := ctl(
		"-socket",
		addr,
		"frobnicate",
	); code != 2 ||
		!strings.Contains(errOut, "Usage:") {
		t.Fatalf("unknown verb: exit %d %q", code, errOut)
	}
}

// With no -socket, weavectl targets the platform layout's control socket;
// nothing listens there in a test, so the call fails rather than hangs.
func TestDefaultSocketUnreachable(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The Windows default is the machine-wide \\.\pipe\weave-control,
		// which a parallel package's test or a real agent may own.
		t.Skip("the default control pipe is machine-wide on Windows")
	}
	dir, err := os.MkdirTemp("", "wctl-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("WEAVE_STATE_DIR", dir)
	code, _, errOut := ctl("status")
	if code != 1 || !strings.Contains(errOut, "weavectl: status:") {
		t.Fatalf("exit %d %q", code, errOut)
	}
}

// weavectl's default is the control socket a weaveboot-started core binds:
// the platform layout's (cmd/weaveboot TestPackagedInvocationKeepsPlatformLayout),
// or the relocated root's when WEAVE_STATE_DIR names one for both.
func TestDefaultSocketIsPlatform(t *testing.T) {
	t.Setenv("WEAVE_STATE_DIR", "")
	want := `\\.\pipe\weave-control`
	if runtime.GOOS != "windows" {
		want = filepath.Join(platform.Paths().RunDir, "control.sock")
	}
	if got := defaultSocket(); got != want {
		t.Fatalf("default socket %q, want %q", got, want)
	}
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	t.Setenv("WEAVE_STATE_DIR", root)
	if got := defaultSocket(); got != filepath.Join(root, "run", "control.sock") {
		t.Fatalf("relocated default socket %q", got)
	}
}
