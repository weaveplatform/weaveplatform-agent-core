package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/weaveboot"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/winsvc"
)

func stubBoot(t *testing.T, fn func(context.Context, weaveboot.Options) error) {
	t.Helper()
	orig := bootRun
	bootRun = fn
	t.Cleanup(func() { bootRun = orig })
}

func TestArgsReachWeaveboot(t *testing.T) {
	state := t.TempDir()
	var got weaveboot.Options
	stubBoot(t, func(_ context.Context, o weaveboot.Options) error {
		got = o
		return nil
	})
	if code := run(
		[]string{"-state-dir", state, "--", "-channel", "vsock:2010"},
		&bytes.Buffer{},
	); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got.CoreDir != filepath.Join(state, "core") {
		t.Fatalf("CoreDir = %q", got.CoreDir)
	}
	want := []string{"--state-dir", state, "-channel", "vsock:2010"}
	if !reflect.DeepEqual(got.AgentArgs, want) {
		t.Fatalf("AgentArgs = %q, want %q", got.AgentArgs, want)
	}
	if got.VerifyCore == nil || got.Log == nil {
		t.Fatal("weaveboot started without a core verifier or logger")
	}
	// SIGHUP is forwarded where there is one; Windows has nothing to forward.
	if (got.Forward != nil) != (len(forwardSignals) > 0) {
		t.Fatalf("Forward = %v with forwardSignals %v", got.Forward, forwardSignals)
	}
}

// The state dir must reach core even when only the environment names it,
// or core and weaveboot would disagree about where state lives.
func TestStateDirFromEnvironment(t *testing.T) {
	state := t.TempDir()
	t.Setenv("WEAVE_STATE_DIR", state)
	var got weaveboot.Options
	stubBoot(t, func(_ context.Context, o weaveboot.Options) error {
		got = o
		return nil
	})
	if code := run(nil, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(got.AgentArgs) != 2 || got.AgentArgs[1] != state {
		t.Fatalf("AgentArgs = %q", got.AgentArgs)
	}
}

func TestFailureExitsNonZero(t *testing.T) {
	stubBoot(t, func(context.Context, weaveboot.Options) error { return errors.New("no core") })
	var errOut bytes.Buffer
	if code := run([]string{"-state-dir", t.TempDir()}, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "no core") {
		t.Fatalf("failure not logged: %q", errOut.String())
	}
}

func TestFlagErrors(t *testing.T) {
	stubBoot(t, func(context.Context, weaveboot.Options) error {
		t.Fatal("bad flags must not start weaveboot")
		return nil
	})
	if code := run([]string{"-bogus"}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := run([]string{"-help"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("-help exit %d, want 0", code)
	}
}

// Without a stub, run reaches the real supervisor, which fails cleanly
// when there is no core to start.
func TestRealSupervisorWithoutCore(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "core"), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := run([]string{"-state-dir", state}, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

// stubSCM makes entry believe the SCM started it; runService plays the SCM,
// running the body until stop is closed.
func stubSCM(t *testing.T, svc bool, detectErr error, run func(func(context.Context) error) error) {
	t.Helper()
	origIs, origRun := isService, runService
	t.Cleanup(func() { isService, runService = origIs, origRun })
	isService = func() (bool, error) { return svc, detectErr }
	runService = run
}

// Under the SCM, weaveboot's log and core's output go to a file under the
// state root's log dir — there is no stderr — and a stop is a context
// cancel, the same path SIGTERM takes.
func TestServiceModeLogsToFileAndStopsOnCancel(t *testing.T) {
	state := t.TempDir()
	var got weaveboot.Options
	stubBoot(t, func(ctx context.Context, o weaveboot.Options) error {
		got = o
		o.Log.Info("core supervised")
		<-ctx.Done()
		return nil
	})
	stubSCM(t, true, nil, func(body func(context.Context) error) error {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(10*time.Millisecond, cancel)
		return body(ctx)
	})
	var errOut bytes.Buffer
	if code := entry([]string{"-state-dir", state}, &bytes.Buffer{}, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if errOut.Len() != 0 {
		t.Fatalf("service mode wrote to stderr: %q", errOut.String())
	}
	logged, err := os.ReadFile(filepath.Join(state, "logs", "weaveboot.log"))
	if err != nil || !strings.Contains(string(logged), "core supervised") {
		t.Fatalf("service log = %q, %v", logged, err)
	}
	if got.Output == nil {
		t.Fatal("core's output not redirected to the service log")
	}
}

// A body failure must surface as a non-zero exit so the SCM's recovery
// restarts the service.
func TestServiceModeFailure(t *testing.T) {
	stubBoot(t, func(context.Context, weaveboot.Options) error { return errors.New("no core") })
	stubSCM(t, true, nil, func(body func(context.Context) error) error {
		return body(context.Background())
	})
	if code := entry(
		[]string{"-state-dir", t.TempDir()},
		&bytes.Buffer{},
		&bytes.Buffer{},
	); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	// The SCM reporting an error of its own with a clean body is a failure.
	stubBoot(t, func(context.Context, weaveboot.Options) error { return nil })
	stubSCM(t, true, nil, func(body func(context.Context) error) error {
		body(context.Background()) //nolint:errcheck
		return winsvc.ErrUnexpectedExit
	})
	if code := entry(
		[]string{"-state-dir", t.TempDir()},
		&bytes.Buffer{},
		&bytes.Buffer{},
	); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	// Flag errors under the SCM land in the service log, not nowhere.
	state := t.TempDir()
	t.Setenv("WEAVE_STATE_DIR", state)
	stubSCM(
		t,
		true,
		nil,
		func(body func(context.Context) error) error { return body(context.Background()) },
	)
	if code := entry([]string{"-bogus"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("bad flag exit %d, want 2", code)
	}
	logged, _ := os.ReadFile(filepath.Join(state, "logs", "weaveboot.log"))
	if !strings.Contains(string(logged), "bogus") {
		t.Fatalf("flag error not logged: %q", logged)
	}
}

// Detected as a service but the SCM never called back, or detection
// failed: weaveboot runs interactively exactly as before.
func TestNotActuallyAServiceRunsInteractively(t *testing.T) {
	for name, stub := range map[string]func(*testing.T){
		"dispatcher refused": func(t *testing.T) {
			stubSCM(t, true, nil, func(func(context.Context) error) error { return winsvc.ErrNotService })
		},
		"detection failed": func(t *testing.T) {
			stubSCM(t, false, errors.New("snapshot"), func(func(context.Context) error) error {
				t.Fatal("dispatcher started after failed detection")
				return nil
			})
		},
	} {
		stub(t)
		ran := false
		stubBoot(t, func(context.Context, weaveboot.Options) error { ran = true; return nil })
		var errOut bytes.Buffer
		if code := entry(
			[]string{"-state-dir", t.TempDir()},
			&bytes.Buffer{},
			&errOut,
		); code != 0 ||
			!ran {
			t.Fatalf("%s: exit %d ran=%v", name, code, ran)
		}
	}
}

// The service log is bounded: past the limit the old log becomes .1 and a
// fresh one starts.
func TestServiceLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weaveboot.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxServiceLog+1), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openServiceLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("log not rotated: %v", err)
	}
	if fi, err := os.Stat(path + ".1"); err != nil || fi.Size() != maxServiceLog+1 {
		t.Fatalf("previous generation missing: %v", err)
	}
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openServiceLog(filepath.Join(blocker, "logs")); err == nil {
		t.Fatal("log opened under a file")
	}
}

// A log that cannot be opened must not stop the agent.
func TestServiceModeRunsWithoutLog(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	stubBoot(t, func(context.Context, weaveboot.Options) error { ran = true; return nil })
	if code := boot(
		context.Background(),
		[]string{"-state-dir", blocker},
		&bytes.Buffer{},
		true,
		nil,
	); code != 0 ||
		!ran {
		t.Fatalf("exit %d ran=%v", code, ran)
	}
}

func TestServiceSubcommandDispatch(t *testing.T) {
	var out bytes.Buffer
	if code := entry(
		[]string{"service", "help"},
		&out,
		&bytes.Buffer{},
	); code != 0 ||
		!strings.Contains(out.String(), "install") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

// The packaged invocation (no --state-dir, no WEAVE_STATE_DIR) must leave
// core on the platform layout, so its control socket is the one weavectl
// dials by default (cmd/weavectl TestDefaultSocketIsPlatform) on every OS.
// Passing the platform StateDir as --state-dir relocated the run dir under it.
func TestPackagedInvocationKeepsPlatformLayout(t *testing.T) {
	t.Setenv("WEAVE_STATE_DIR", "")
	var got weaveboot.Options
	stubBoot(t, func(_ context.Context, o weaveboot.Options) error {
		got = o
		return nil
	})
	if code := run(
		[]string{"--", "--modules-dir", "/usr/lib/weave/modules"},
		&bytes.Buffer{},
	); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if want := []string{
		"--modules-dir",
		"/usr/lib/weave/modules",
	}; !reflect.DeepEqual(
		got.AgentArgs,
		want,
	) {
		t.Fatalf("AgentArgs = %q, want %q", got.AgentArgs, want)
	}
	// Core reads --state-dir and resolves its layout from it, as weave-agent does.
	fs := flag.NewFlagSet("weave-agent", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "", "")
	fs.String("modules-dir", "", "")
	if err := fs.Parse(got.AgentArgs); err != nil {
		t.Fatal(err)
	}
	coreSocket := layout.Resolve(*stateDir).ControlSocket()
	want := `\\.\pipe\weave-control`
	if runtime.GOOS != "windows" {
		want = filepath.Join(platform.Paths().RunDir, "control.sock")
	}
	if coreSocket != want {
		t.Fatalf("core binds %q, want the platform's %q", coreSocket, want)
	}
	if got.CoreDir != filepath.Join(platform.Paths().StateDir, "core") {
		t.Fatalf("CoreDir = %q", got.CoreDir)
	}
}
