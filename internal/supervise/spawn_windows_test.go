package supervise

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	winsec "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	"golang.org/x/sys/windows"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// restrictedSelfToken is a primary token for the tester's own user — the
// same restricted token the service drop uses, which CreateProcessAsUser
// accepts without SE_ASSIGNPRIMARYTOKEN. It stands in for WTSQueryUserToken,
// which only LocalSystem may call.
func restrictedSelfToken() (foundation.HANDLE, error) {
	var proc foundation.HANDLE
	if err := threading.OpenProcessToken(
		threading.GetCurrentProcess(),
		winsec.TOKEN_ACCESS_MASK(
			windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
		),
		&proc,
	); err != nil {
		return 0, err
	}
	defer foundation.CloseHandle(proc) //nolint:errcheck
	var restricted foundation.HANDLE
	err := winsec.CreateRestrictedToken(
		proc,
		winsec.DISABLE_MAX_PRIVILEGE,
		nil,
		nil,
		nil,
		&restricted,
	)
	return restricted, err
}

// selfSession is a console session for the tester's own logon session,
// with the LocalSystem-only token call and the interactive desktop replaced:
// a CI runner's process may not be on an interactive window station at all.
// variant distinguishes sessions (by user name; the id must stay real).
func selfSession(t *testing.T, variant int) session.Session {
	t.Helper()
	var id uint32
	if err := remotedesktop.ProcessIdToSessionId(uint32(os.Getpid()), &id); err != nil {
		t.Fatalf("ProcessIdToSessionId: %v", err)
	}
	origTok, origDesk := queryUserToken, interactiveDesktop
	queryUserToken = func(uint32) (foundation.HANDLE, error) { return restrictedSelfToken() }
	interactiveDesktop = ""
	t.Cleanup(func() { queryUserToken, interactiveDesktop = origTok, origDesk })
	return session.Session{
		ID:   strconv.FormatUint(uint64(id), 10),
		User: "tester" + strconv.Itoa(variant),
	}
}

func canLaunchIntoSelf(*testing.T) {}

func TestApplyPrivilegeWindows(t *testing.T) {
	// service: a restricted primary token rides SysProcAttr; the cleanup
	// closes our copy of the handle.
	cmd := exec.Command(os.Args[0])
	cleanup, err := applyPrivilege(cmd, testManifest())
	if err != nil {
		t.Fatalf("service privilege: %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token == 0 {
		t.Fatal("no restricted token assigned")
	}
	cleanup()

	sys := testManifest()
	sys.Privilege = manifest.PrivilegeSystem
	cmd = exec.Command(os.Args[0])
	cleanup, err = applyPrivilege(cmd, sys)
	if err != nil || (cmd.SysProcAttr != nil && cmd.SysProcAttr.Token != 0) {
		t.Fatalf("system privilege must run with core's own token: %v", err)
	}
	cleanup()

	usr := testManifest()
	usr.Privilege = manifest.PrivilegeUser
	if _, err := applyPrivilege(
		exec.Command(os.Args[0]),
		usr,
	); err == nil ||
		!strings.Contains(err.Error(), "no system-session identity") {
		t.Fatalf("user privilege: %v", err)
	}
	tgt, _ := newTarget(layout.Layout{}, usr, nil)
	if _, err := tgt.start(
		os.Args[0],
		nil,
		nil,
		nil,
	); err == nil ||
		!strings.Contains(err.Error(), "privilege setup") {
		t.Fatalf("start with no identity: %v", err)
	}
}

func TestSystemTargetWindows(t *testing.T) {
	if _, err := (&target{m: testManifest()}).stageBinary(
		`C:\m.exe`,
	); !errors.Is(
		err,
		errNoExecDir,
	) {
		t.Fatalf("stageBinary with no layout = %v", err)
	}
	lay := layout.Resolve(t.TempDir())
	tgt, err := newTarget(lay, testManifest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.close()
	installed := filepath.Join(t.TempDir(), "m.exe")
	if err := os.WriteFile(installed, []byte("image"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Staged under the module's ExecDir, in a fresh directory per launch,
	// and never the installed file itself.
	first, err := tgt.stageBinary(installed)
	if err != nil {
		t.Fatalf("stageBinary: %v", err)
	}
	if filepath.Dir(filepath.Dir(first)) != lay.ModuleExecDir(testManifest().ID) {
		t.Fatalf("staged at %s", first)
	}
	if b, err := os.ReadFile(first); err != nil || string(b) != "image" {
		t.Fatalf("staged copy = %q %v", b, err)
	}
	// A copy that is still open (as a running image is) does not stop the
	// next launch; one that is not is cleared by it.
	held, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tgt.stageBinary(installed)
	held.Close()
	if err != nil || second == first {
		t.Fatalf("restage over a held copy = %q %v", second, err)
	}
	if _, err := tgt.stageBinary(installed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("stale staged copy kept: %v", err)
	}
	// The installed file is free to go while a copy is staged.
	if err := os.Remove(installed); err != nil {
		t.Fatalf("installed binary locked by staging: %v", err)
	}
	if _, err := tgt.stageBinary(installed); err == nil {
		t.Fatal("staged a binary that is not there")
	}
	// ExecDir unusable: a file where the module's directory belongs.
	blocked := layout.Resolve(t.TempDir())
	if err := os.MkdirAll(blocked.ExecDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocked.ModuleExecDir(testManifest().ID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&target{layout: blocked, m: testManifest()}).stageBinary(first); err == nil {
		t.Fatal("staged into a file")
	}
	if err := tgt.prepareSocketDir("", ""); err != nil {
		t.Fatal(err)
	}
	l, err := tgt.listenHost(t.Context(), `\\.\pipe\weave-test-sys-`+strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("listenHost: %v", err)
	}
	l.Close()
	if _, err := tgt.start(
		`C:\definitely\absent.exe`,
		nil,
		nil,
		nil,
	); err == nil ||
		!strings.Contains(err.Error(), "exec:") {
		t.Fatalf("start of a missing binary: %v", err)
	}
}

func TestSessionPipeSDDL(t *testing.T) {
	if got := sessionPipeSDDL(
		"S-1-5-21-1-2-3-1001",
	); got != "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("SDDL = %q", got)
	}
}

func TestSessionTargetWindows(t *testing.T) {
	sess := selfSession(t, 1)
	tgt, err := newTarget(layout.Layout{}, userManifest(), &sess)
	if err != nil {
		t.Fatalf("newTarget: %v", err)
	}
	if tgt.token == 0 || !strings.HasPrefix(tgt.sid, "S-1-5-") {
		t.Fatalf("token=%v sid=%q", tgt.token, tgt.sid)
	}
	l, err := tgt.listenHost(t.Context(), `\\.\pipe\weave-test-user-`+strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatalf("listenHost with the user's SDDL: %v", err)
	}
	l.Close()
	tgt.close()
	tgt.close() // idempotent
	if tgt.token != 0 {
		t.Fatal("token not released")
	}
}

func TestSessionTargetFailuresWindows(t *testing.T) {
	if _, err := newTarget(
		layout.Layout{},
		userManifest(),
		&session.Session{ID: "console"},
	); err == nil {
		t.Fatal("non-numeric session id accepted")
	}
	orig := queryUserToken
	t.Cleanup(func() { queryUserToken = orig })
	queryUserToken = func(uint32) (foundation.HANDLE, error) { return 0, errors.New("privilege not held") }
	if _, err := newTarget(
		layout.Layout{},
		userManifest(),
		&session.Session{ID: "1"},
	); err == nil ||
		!strings.Contains(err.Error(), "LocalSystem") {
		t.Fatalf("token failure: %v", err)
	}
	// A handle that is not a token yields no SID, and the target is not built.
	queryUserToken = func(uint32) (foundation.HANDLE, error) {
		h, err := windows.CreateEvent(nil, 0, 0, nil)
		return foundation.HANDLE(h), err
	}
	if _, err := newTarget(layout.Layout{}, userManifest(), &session.Session{ID: "1"}); err == nil {
		t.Fatal("non-token handle accepted")
	}
	// Not a null handle: CreateEnvironmentBlock(NULL) succeeds with the
	// system-only environment.
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(ev) //nolint:errcheck
	if _, err := environmentFor(foundation.HANDLE(ev)); err == nil {
		t.Fatal("environment for a handle that is not a token")
	}
}

// The real WTSQueryUserToken needs LocalSystem and a user at the console;
// CI runners have neither, so this only runs where both hold.
func TestQueryUserTokenReal(t *testing.T) {
	src := session.Console()
	s, ok, err := src.Console()
	if err != nil || !ok {
		t.Skipf("no console user session here (ok=%v err=%v)", ok, err)
	}
	id, _ := strconv.ParseUint(s.ID, 10, 32)
	tok, err := queryUserToken(uint32(id))
	if err != nil {
		t.Skipf(
			"WTSQueryUserToken unavailable (core runs as LocalSystem; tests usually do not): %v",
			err,
		)
	}
	defer foundation.CloseHandle(tok) //nolint:errcheck
	if sid, err := tokenUserSID(tok); err != nil || sid == "" {
		t.Fatalf("console user's SID: %q %v", sid, err)
	}
}

func TestEnvironmentForSelf(t *testing.T) {
	tok, err := restrictedSelfToken()
	if err != nil {
		t.Fatal(err)
	}
	defer foundation.CloseHandle(tok) //nolint:errcheck
	env, err := environmentFor(tok)
	if err != nil {
		t.Fatalf("environmentFor: %v", err)
	}
	found := false
	for _, kv := range env {
		if strings.HasPrefix(strings.ToUpper(kv), "USERPROFILE=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no USERPROFILE in the user's environment: %q", env)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startAsUser carries stdio, environment and exit status like os/exec.
func TestStartAsUser(t *testing.T) {
	selfSession(t, 1) // desktop seam
	tok, err := restrictedSelfToken()
	if err != nil {
		t.Fatal(err)
	}
	defer foundation.CloseHandle(tok) //nolint:errcheck
	var out, errOut syncBuf
	c, err := startAsUser(
		tok,
		os.Args[0],
		append(os.Environ(), childEchoEnv+"=WEAVE_PROBE", "WEAVE_PROBE=hello"),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("startAsUser: %v", err)
	}
	if c.pid == 0 {
		t.Fatal("no pid")
	}
	code, werr := c.wait()
	if code != 3 || werr == nil || !strings.Contains(werr.Error(), "exit status 3") {
		t.Fatalf("wait = %d %v", code, werr)
	}
	if !strings.Contains(out.String(), "out WEAVE_PROBE=hello") ||
		!strings.Contains(errOut.String(), "err line") {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if err := c.kill(); err != nil {
		t.Fatalf("kill after exit must be a no-op: %v", err)
	}

	if _, err := startAsUser(tok, `C:\definitely\absent.exe`, nil, &out, &errOut); err == nil {
		t.Fatal("started a missing binary")
	}
}

func TestStartAsUserKill(t *testing.T) {
	selfSession(t, 1)
	tok, err := restrictedSelfToken()
	if err != nil {
		t.Fatal(err)
	}
	defer foundation.CloseHandle(tok) //nolint:errcheck
	c, err := startAsUser(
		tok,
		os.Args[0],
		append(os.Environ(), childSleepEnv+"=1"),
		&syncBuf{},
		&syncBuf{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	done := make(chan int, 1)
	go func() { code, _ := c.wait(); done <- code }()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("killed child exit code = %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("kill did not end the child")
	}
}

// The real interactive desktop: on a host whose tests run on WinSta0 the
// child starts there; on a runner without one, either the create or the
// child's initialisation fails. Either way the branch runs; only a hang is
// a failure.
func TestStartAsUserInteractiveDesktop(t *testing.T) {
	tok, err := restrictedSelfToken()
	if err != nil {
		t.Fatal(err)
	}
	defer foundation.CloseHandle(tok) //nolint:errcheck
	c, err := startAsUser(
		tok,
		os.Args[0],
		append(os.Environ(), childEchoEnv+"=X"),
		&syncBuf{},
		&syncBuf{},
	)
	if err != nil {
		t.Skipf("no access to %s here: %v", interactiveDesktop, err)
	}
	done := make(chan int, 1)
	go func() { code, _ := c.wait(); done <- code }()
	select {
	case code := <-done:
		t.Logf("child on %s exited %d", interactiveDesktop, code)
	case <-time.After(30 * time.Second):
		c.kill() //nolint:errcheck
		t.Fatal("child on the interactive desktop hung")
	}
}

// A per-user launch target that cannot be built is a launch failure.
func TestLaunchTargetFailure(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	sup.Sessions = fixedSessions(session.Session{ID: "console", User: "x"})
	if err := sup.Add(
		Spec{Manifest: userManifest(), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "launch target", 10*time.Second)
}

func TestWindowsNoops(t *testing.T) {
	closeJob(jobHandle{})
	killed := false
	killProc(&child{kill: func() error { killed = true; return nil }}, jobHandle{})
	if !killed {
		t.Fatal("killProc without a job did not kill the child")
	}
}

// A contained child dies when its job is terminated, and the job handle
// closes cleanly afterwards.
func TestJobContainment(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childSleepEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	job, err := postSpawn(cmd.Process.Pid)
	if err != nil {
		cmd.Process.Kill() //nolint:errcheck
		t.Fatalf("postSpawn: %v", err)
	}
	if job.h == 0 {
		t.Fatal("no job object")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	killProc(commandChild(cmd), job)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill() //nolint:errcheck
		t.Fatal("terminating the job did not kill the child")
	}
	closeJob(job)
	if _, err := postSpawn(0x7FFFFFF0); err == nil {
		t.Fatal("contained a nonexistent process")
	}
}
