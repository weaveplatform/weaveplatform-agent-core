//go:build !windows

package supervise

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// asRoot makes the credential code believe core runs as root, with the
// service account resolving to the invoking user, so the drop paths run
// without privileges: a "drop" to one's own uid is always permitted.
func asRoot(t *testing.T, lookup func(string) (*user.User, error)) {
	t.Helper()
	origEuid, origLookup := geteuid, lookupUser
	geteuid = func() int { return 0 }
	lookupUser = lookup
	t.Cleanup(func() { geteuid, lookupUser = origEuid, origLookup })
}

func self(t *testing.T) *user.User {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	return u
}

// selfSession is a console session belonging to the user running the tests,
// which a non-root core may launch into. variant distinguishes sessions.
func selfSession(t *testing.T, variant int) session.Session {
	t.Helper()
	me := self(t)
	uid, err := strconv.ParseUint(me.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return session.Session{
		ID: "s" + strconv.Itoa(variant), User: me.Username, UID: uint32(uid),
		Env: []string{"XDG_SESSION_ID=s" + strconv.Itoa(variant)},
	}
}

// canLaunchIntoSelf reports whether this host can start a process in the
// tester's own session. On macOS that goes through launchctl asuser, which
// needs the user's GUI launchd domain: a CI runner without a logged-in GUI
// user has none.
func canLaunchIntoSelf(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return
	}
	out, err := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(os.Getuid()), "/usr/bin/true").
		CombinedOutput()
	if err != nil {
		t.Skipf("launchctl asuser into own session unavailable here: %v %s", err, out)
	}
}

func testTarget(t *testing.T, m *manifest.Manifest, sess *session.Session) *target {
	t.Helper()
	dir, err := os.MkdirTemp("", "wvt-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lay := layout.Resolve(dir)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}
	tgt, err := newTarget(lay, m, sess)
	if err != nil {
		t.Fatalf("newTarget: %v", err)
	}
	return tgt
}

func TestServiceAccount(t *testing.T) {
	want := "weave-agent"
	if runtime.GOOS == "darwin" {
		want = "_weaveagent"
	}
	if got := serviceAccount(); got != want {
		t.Fatalf("serviceAccount() = %q, want %q", got, want)
	}
}

func TestSystemCredsUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if c, err := systemCreds(testManifest()); c != nil || err != nil {
		t.Fatalf("non-root core must not drop: %+v %v", c, err)
	}
}

func TestSystemCredsAsRoot(t *testing.T) {
	me := self(t)
	asRoot(t, func(name string) (*user.User, error) {
		if name != serviceAccount() {
			t.Errorf("looked up %q, want the service account", name)
		}
		return me, nil
	})

	mf := testManifest()
	c, err := systemCreds(mf)
	if err != nil || c == nil || me.Uid != strconv.FormatUint(uint64(c.uid), 10) ||
		me.Gid != strconv.FormatUint(uint64(c.gid), 10) {
		t.Fatalf("service drop = %+v err=%v, want %s:%s", c, err, me.Uid, me.Gid)
	}

	sys := testManifest()
	sys.Privilege = manifest.PrivilegeSystem
	if c, err := systemCreds(sys); c != nil || err != nil {
		t.Fatalf("system-privilege module must not drop: %+v %v", c, err)
	}

	usr := testManifest()
	usr.Privilege = manifest.PrivilegeUser
	if _, err := systemCreds(
		usr,
	); err == nil ||
		!strings.Contains(err.Error(), "no system-session identity") {
		t.Fatalf("user privilege in the system session: %v", err)
	}
	if _, err := newTarget(layout.Layout{}, usr, nil); err == nil {
		t.Fatal("newTarget accepted a privilege with no identity")
	}
}

// A dropped module gets a root-owned staged copy of its binary, a socket dir
// it owns under traversable parents, and admission to its host socket.
func TestDroppedTargetPreparesTheTree(t *testing.T) {
	me := self(t)
	asRoot(t, func(string) (*user.User, error) { return me, nil })
	tgt := testTarget(t, testManifest(), nil)
	if tgt.drop == nil {
		t.Fatal("no drop as root")
	}

	src := filepath.Join(t.TempDir(), "mod")
	if err := os.WriteFile(src, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := tgt.stageBinary(src)
	if err != nil {
		t.Fatalf("stageBinary: %v", err)
	}
	if staged == src || !strings.HasPrefix(staged, tgt.layout.RunDir) {
		t.Fatalf("staged at %s", staged)
	}
	fi, err := os.Stat(staged)
	if err != nil || fi.Mode().Perm() != 0o555 {
		t.Fatalf("staged binary mode = %v err=%v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(staged); !bytes.Equal(b, []byte("binary")) {
		t.Fatal("staged copy differs")
	}
	// Restaging replaces the read-only copy.
	if _, err := tgt.stageBinary(src); err != nil {
		t.Fatalf("restage: %v", err)
	}
	if _, err := tgt.stageBinary(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("staged a missing binary")
	}

	dir := tgt.layout.ModuleRunDir("testmod")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "host.sock")
	if err := os.WriteFile(host, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tgt.prepareSocketDir(dir, host); err != nil {
		t.Fatalf("prepareSocketDir: %v", err)
	}
	for _, d := range []string{tgt.layout.RunDir, filepath.Dir(dir)} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o711 {
			t.Fatalf("%s mode %v, want search-only for others", d, fi.Mode().Perm())
		}
	}
	if err := tgt.prepareSocketDir(dir, filepath.Join(dir, "absent.sock")); err == nil {
		t.Fatal("chown of a missing host socket succeeded")
	}
	if err := tgt.prepareSocketDir(filepath.Join(dir, "absent"), host); err == nil {
		t.Fatal("chown of a missing socket dir succeeded")
	}

	if err := tgt.authorizePeer()(ipc.PeerCred{HasUID: true, UID: tgt.drop.uid}); err != nil {
		t.Fatalf("dropped uid refused: %v", err)
	}
	cmd := tgt.buildCmd("/bin/true", nil, nil, nil)
	if c := cmd.SysProcAttr.Credential; c == nil || c.Uid != tgt.drop.uid || c.Gid != tgt.drop.gid {
		t.Fatalf("credential not applied: %+v", cmd.SysProcAttr.Credential)
	}
}

func TestStageBinaryFailures(t *testing.T) {
	me := self(t)
	asRoot(t, func(string) (*user.User, error) { return me, nil })
	tgt := testTarget(t, testManifest(), nil)
	src := filepath.Join(t.TempDir(), "mod")
	if err := os.WriteFile(src, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	// run/bin is a file: the staging dir cannot be made.
	if err := os.WriteFile(filepath.Join(tgt.layout.RunDir, "bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tgt.stageBinary(src); err == nil {
		t.Fatal("staged under a file")
	}
	// A source that is a directory opens but cannot be copied.
	if err := os.Remove(filepath.Join(tgt.layout.RunDir, "bin")); err != nil {
		t.Fatal(err)
	}
	if _, err := tgt.stageBinary(t.TempDir()); err == nil {
		t.Fatal("staged a directory")
	}
	if err := tgt.prepareSocketDir(filepath.Join(t.TempDir(), "x", "y"), "h"); err == nil {
		t.Fatal("opened a missing parent for traversal")
	}
}

// A missing service account fails closed rather than running the module
// as root.
func TestSystemCredsMissingServiceAccount(t *testing.T) {
	asRoot(t, func(string) (*user.User, error) { return nil, errors.New("unknown user") })
	_, err := systemCreds(testManifest())
	if err == nil || !strings.Contains(err.Error(), "missing (installer creates it)") {
		t.Fatalf("err = %v", err)
	}
	if _, err := newTarget(layout.Layout{}, testManifest(), nil); err == nil {
		t.Fatal("newTarget dropped to a missing account")
	}
}

func TestSystemCredsBadIDs(t *testing.T) {
	for _, u := range []*user.User{{Uid: "nope", Gid: "0"}, {Uid: "0", Gid: "nope"}} {
		asRoot(t, func(string) (*user.User, error) { return u, nil })
		if _, err := systemCreds(testManifest()); err == nil {
			t.Fatalf("accepted unparseable ids %+v", u)
		}
	}
}

func TestAuthorizeModulePeer(t *testing.T) {
	authz := (&target{m: testManifest()}).authorizePeer()
	if err := authz(ipc.PeerCred{}); err != nil {
		t.Fatalf("peer without uid info must fall back to dir perms: %v", err)
	}
	if err := authz(ipc.PeerCred{HasUID: true, UID: 0}); err != nil {
		t.Fatalf("root refused: %v", err)
	}
	if err := authz(ipc.PeerCred{HasUID: true, UID: uint32(os.Getuid())}); err != nil {
		t.Fatalf("core's own uid refused: %v", err)
	}
	if err := authz(ipc.PeerCred{HasUID: true, UID: 4242424}); err == nil {
		t.Fatal("a foreign uid was admitted")
	}
}

func TestContainmentNoops(t *testing.T) {
	closeJob(jobHandle{})
	killed := false
	killProc(&child{kill: func() error { killed = true; return nil }}, jobHandle{})
	if !killed {
		t.Fatal("killProc did not kill the child")
	}
	if j, err := postSpawn(1); err != nil || j != (jobHandle{}) {
		t.Fatalf("postSpawn = %v %v", j, err)
	}
}

// A non-root core launches into its own user's session without a drop,
// and refuses any other user's.
func TestSessionCredsUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	me := self(t)
	sess := selfSession(t, 1)
	c, home, err := sessionCreds(&sess)
	if err != nil || c != nil || home != me.HomeDir {
		t.Fatalf("own session = %+v %q %v", c, home, err)
	}

	other := sess
	other.UID = 0 // root always exists; a non-root core cannot become it
	if _, _, err := sessionCreds(&other); err == nil || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("other user's session: %v", err)
	}
}

func TestSessionCredsAsRoot(t *testing.T) {
	asRoot(t, nil)
	sess := selfSession(t, 1)
	c, _, err := sessionCreds(&sess)
	if err != nil || c == nil || c.uid != sess.UID {
		t.Fatalf("session drop = %+v %v", c, err)
	}
	want, _ := self(t).GroupIds()
	if len(c.groups) != len(want) {
		t.Fatalf("groups = %v, want %v", c.groups, want)
	}
}

func TestSessionCredsFailures(t *testing.T) {
	asRoot(t, nil)
	sess := selfSession(t, 1)
	orig, origGroups := lookupUserID, groupIDs
	t.Cleanup(func() { lookupUserID, groupIDs = orig, origGroups })

	lookupUserID = func(string) (*user.User, error) { return nil, errors.New("no such uid") }
	if _, _, err := sessionCreds(
		&sess,
	); err == nil ||
		!strings.Contains(err.Error(), "console user uid") {
		t.Fatalf("lookup failure: %v", err)
	}
	if _, err := newTarget(layout.Layout{}, testManifest(), &sess); err == nil {
		t.Fatal("newTarget launched for an unknown user")
	}

	lookupUserID = func(string) (*user.User, error) { return &user.User{Uid: "x", Gid: "1"}, nil }
	if _, _, err := sessionCreds(&sess); err == nil {
		t.Fatal("bad uid accepted")
	}

	lookupUserID = func(string) (*user.User, error) { return &user.User{Uid: "501", Gid: "20", Username: "u"}, nil }
	groupIDs = func(*user.User) ([]string, error) { return nil, errors.New("directory down") }
	if _, _, err := sessionCreds(&sess); err == nil || !strings.Contains(err.Error(), "groups of") {
		t.Fatalf("group failure: %v", err)
	}
	groupIDs = func(*user.User) ([]string, error) { return []string{"20", "staff"}, nil }
	if _, _, err := sessionCreds(&sess); err == nil || !strings.Contains(err.Error(), "group id") {
		t.Fatalf("bad group id: %v", err)
	}
}

// A per-user module's environment is the session user's: core's HOME, USER
// and session variables are replaced, the logind variables added, and the
// handshake variables win over everything.
func TestSessionEnv(t *testing.T) {
	t.Setenv("HOME", "/var/root")
	t.Setenv("TMPDIR", "/var/folders/root")
	t.Setenv("WAYLAND_DISPLAY", "wayland-root")
	t.Setenv("WEAVE_LOG_LEVEL", "debug")
	sess := selfSession(t, 1)
	sess.Env = append(sess.Env, "WAYLAND_DISPLAY=wayland-0")
	tgt := &target{m: testManifest(), sess: &sess, home: "/home/alice"}
	env := tgt.env([]string{"WEAVE_HANDSHAKE_TOKEN=t", "USER=override"})
	get := func(k string) (string, int) {
		v, n := "", 0
		for _, kv := range env {
			if key, val, _ := strings.Cut(kv, "="); key == k {
				v = val
				n++
			}
		}
		return v, n
	}
	for k, want := range map[string]string{
		"HOME": "/home/alice", "LOGNAME": sess.User, "USER": "override",
		"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_ID": "s1",
		"WEAVE_LOG_LEVEL": "debug", "WEAVE_HANDSHAKE_TOKEN": "t",
	} {
		if v, n := get(k); v != want || n != 1 {
			t.Errorf("%s = %q (%d copies), want %q", k, v, n, want)
		}
	}
	if _, n := get("TMPDIR"); n != 0 {
		t.Error("core's TMPDIR leaked into the user's session")
	}

	sys := &target{m: testManifest()}
	if env := sys.env(
		[]string{"A=1"},
	); env[len(env)-1] != "A=1" ||
		len(env) != len(os.Environ())+1 {
		t.Fatal("system module env is not core's plus the handshake")
	}
}

// The session command and its working directory, without exec'ing.
func TestSessionBuildCmd(t *testing.T) {
	sess := selfSession(t, 1)
	home := t.TempDir()
	tgt := &target{m: testManifest(), sess: &sess, home: home}
	cmd := tgt.buildCmd("/opt/mod", nil, nil, nil)
	if cmd.Dir != home {
		t.Fatalf("cmd.Dir = %q, want the user's home", cmd.Dir)
	}
	if cmd.SysProcAttr.Credential != nil {
		t.Fatal("credential set without a drop")
	}
	tgt.home = filepath.Join(home, "absent")
	if cmd := tgt.buildCmd("/opt/mod", nil, nil, nil); cmd.Dir != "" {
		t.Fatalf("missing home used as cwd: %q", cmd.Dir)
	}

	tgt.drop = &creds{uid: 501, gid: 20, groups: []uint32{20, 12}}
	cmd = tgt.buildCmd("/opt/mod", nil, nil, nil)
	if runtime.GOOS == "darwin" {
		if cmd.SysProcAttr.Credential != nil {
			t.Fatal("darwin: launchctl must run as root; chroot drops")
		}
		want := []string{
			"/bin/launchctl",
			"asuser",
			strconv.FormatUint(uint64(sess.UID), 10),
			"/usr/sbin/chroot",
			"-u",
			"501",
			"-g",
			"20",
			"-G",
			"20,12",
			"/",
			"/opt/mod",
		}
		if !slices.Equal(cmd.Args, want) {
			t.Fatalf("args = %q, want %q", cmd.Args, want)
		}
	} else {
		if c := cmd.SysProcAttr.Credential; c == nil || c.Uid != 501 ||
			!slices.Equal(c.Groups, []uint32{20, 12}) {
			t.Fatalf("credential = %+v", c)
		}
		if !slices.Equal(cmd.Args, []string{"/opt/mod"}) {
			t.Fatalf("args = %q", cmd.Args)
		}
	}
}

func TestStartExecFailure(t *testing.T) {
	tgt := &target{m: testManifest()}
	if _, err := tgt.start(
		filepath.Join(t.TempDir(), "absent"),
		nil,
		nil,
		nil,
	); err == nil ||
		!strings.Contains(err.Error(), "exec:") {
		t.Fatalf("start of a missing binary: %v", err)
	}
}

// The per-module socket dir cannot be created: the launch fails before any
// listener or process exists.
func TestLaunchSocketDirUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	sup, logs, _ := capturingSupervisor(t)
	if err := os.MkdirAll(sup.Layout.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sup.Layout.RunDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sup.Layout.RunDir, 0o700) }) //nolint:errcheck
	if err := sup.Add(Spec{Manifest: testManifest(), BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "launch failed", 10*time.Second)
}

func TestLaunchSocketDirUnderAFile(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	if err := os.WriteFile(
		filepath.Join(sup.Layout.RunDir, "modules"),
		[]byte("x"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := sup.Add(Spec{Manifest: testManifest(), BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "launch failed", 10*time.Second)
}

// A run dir deep enough to push host.sock past sun_path fails at listen.
func TestLaunchHostSocketPathTooLong(t *testing.T) {
	sup, logs, _ := capturingSupervisor(t)
	sup.Layout.RunDir = filepath.Join(sup.Layout.RunDir, strings.Repeat("d", 120))
	if err := sup.Add(Spec{Manifest: testManifest(), BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "host listener", 10*time.Second)
}

// Launch-time failures specific to a dropped module: the staging copy, and
// the socket-dir handover.
func TestLaunchDroppedFailures(t *testing.T) {
	me := self(t)
	asRoot(t, func(string) (*user.User, error) { return me, nil })

	sup, logs, _ := capturingSupervisor(t)
	if err := sup.Add(
		Spec{Manifest: testManifest(), BinPath: filepath.Join(t.TempDir(), "absent")},
	); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "staging binary", 10*time.Second)
}

func TestLaunchTargetFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	sup, logs, _ := capturingSupervisor(t)
	sess := selfSession(t, 1)
	sess.UID = 0
	sup.Sessions = fixedSessions(sess)
	if err := sup.Add(
		Spec{Manifest: userManifest(), BinPath: fixture(t, "testmodule")},
	); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "launch target", 10*time.Second)
}
