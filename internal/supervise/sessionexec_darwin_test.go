package supervise

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// fakeCreds stands in for the process credential, as root would see it.
type fakeCreds struct {
	uid, gid int
	groups   []int
	// regain lets setuid(0) succeed after the drop: a saved uid left behind.
	regain bool
	// lie leaves the effective uid at 0 whatever setuid was asked.
	lie bool
	// extraGroup is a group the kernel reports beyond those set.
	extraGroup int
	failOn     string
	execErr    error
	execed     []string
}

var errFake = errors.New("fake failure")

func (f *fakeCreds) install(t *testing.T) {
	t.Helper()
	orig := []any{
		setgroups,
		setgid,
		setuid,
		getgroups,
		getuid,
		getEffectiveUID,
		getgid,
		getegid,
		execve,
	}
	t.Cleanup(func() {
		setgroups = orig[0].(func([]int) error)
		setgid = orig[1].(func(int) error)
		setuid = orig[2].(func(int) error)
		getgroups = orig[3].(func() ([]int, error))
		getuid = orig[4].(func() int)
		getEffectiveUID = orig[5].(func() int)
		getgid = orig[6].(func() int)
		getegid = orig[7].(func() int)
		execve = orig[8].(func(string, []string, []string) error)
	})
	fail := func(op string) error {
		if f.failOn == op {
			return errFake
		}
		return nil
	}
	setgroups = func(g []int) error {
		if err := fail("setgroups"); err != nil {
			return err
		}
		f.groups = slices.Clone(g)
		if f.extraGroup != 0 {
			f.groups = append(f.groups, f.extraGroup)
		}
		return nil
	}
	setgid = func(g int) error {
		if err := fail("setgid"); err != nil {
			return err
		}
		f.gid = g
		return nil
	}
	setuid = func(u int) error {
		if u == 0 && f.uid != 0 && !f.regain {
			return syscall.EPERM
		}
		if err := fail("setuid"); err != nil {
			return err
		}
		f.uid = u
		return nil
	}
	getgroups = func() ([]int, error) {
		if err := fail("getgroups"); err != nil {
			return nil, err
		}
		return slices.Clone(f.groups), nil
	}
	getuid = func() int { return f.uid }
	getEffectiveUID = func() int {
		if f.lie {
			return 0
		}
		return f.uid
	}
	getgid = func() int { return f.gid }
	getegid = func() int { return f.gid }
	execve = func(bin string, argv, _ []string) error {
		f.execed = append([]string{bin}, argv...)
		return f.execErr
	}
}

func TestSessionExecDropsThenExecs(t *testing.T) {
	f := &fakeCreds{groups: []int{0, 1, 80}}
	f.install(t)
	var out bytes.Buffer
	code := SessionExec([]string{"501", "20", "20,12,80", "/opt/mod"}, &out)
	// The fake exec returns, so SessionExec reports it as a failed exec; what
	// matters is what it ran and as whom.
	if code != 1 || !slices.Equal(f.execed, []string{"/opt/mod", "/opt/mod"}) {
		t.Fatalf("exit %d, exec %q: %s", code, f.execed, out.String())
	}
	if f.uid != 501 || f.gid != 20 || !slices.Equal(f.groups, []int{20, 12, 80}) {
		t.Fatalf("identity %d:%d %v", f.uid, f.gid, f.groups)
	}
	f.execErr = syscall.ENOENT
	out.Reset()
	if code := SessionExec([]string{"501", "20", "20", "/opt/mod"}, &out); code != 1 ||
		!strings.Contains(out.String(), "no such file") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

func TestSessionExecRefusesBadArguments(t *testing.T) {
	f := &fakeCreds{}
	f.install(t)
	too := make([]string, ngroupsMax+1)
	for i := range too {
		too[i] = strconv.Itoa(100 + i)
	}
	for name, args := range map[string][]string{
		"count":    {"501", "20", "20"},
		"uid":      {"x", "20", "20", "/opt/mod"},
		"gid":      {"501", "-1", "20", "/opt/mod"},
		"group":    {"501", "20", "20,", "/opt/mod"},
		"root":     {"0", "0", "0", "/opt/mod"},
		"groups":   {"501", "20", strings.Join(too, ","), "/opt/mod"},
		"relative": {"501", "20", "20", "opt/mod"},
	} {
		var out bytes.Buffer
		if code := SessionExec(args, &out); code != 2 || out.Len() == 0 {
			t.Errorf("%s: exit %d %q", name, code, out.String())
		}
	}
	if f.execed != nil || f.uid != 0 {
		t.Fatal("a refused launch changed identity or ran something")
	}
}

// Every way the drop can fall short stops the launch before the module runs.
func TestSessionExecFailsClosed(t *testing.T) {
	for name, f := range map[string]*fakeCreds{
		"setgroups":  {failOn: "setgroups"},
		"setgid":     {failOn: "setgid"},
		"setuid":     {failOn: "setuid"},
		"getgroups":  {failOn: "getgroups"},
		"euid":       {lie: true},
		"extragroup": {extraGroup: 80},
		"regain":     {regain: true},
	} {
		t.Run(name, func(t *testing.T) {
			f.install(t)
			var out bytes.Buffer
			if code := SessionExec([]string{"501", "20", "20,12", "/opt/mod"}, &out); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if f.execed != nil {
				t.Fatalf("module exec'd after a failed drop: %s", out.String())
			}
		})
	}
}

// The real thing, as root with a console user logged in (a macOS guest; no
// CI runner has both): core's own launch path — launchctl asuser, then this
// binary in session-exec mode — runs a script that reports who it is and
// which bootstrap it has.
func TestSessionLaunchDropsForReal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/dev/console", &st); err != nil || st.Uid == 0 {
		t.Skip("no console user")
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "wvsx-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "who")
	body := "#!/bin/sh\nid -u; id -ru; id -g; id -rg; id -G; /bin/launchctl managername\n"
	if err := os.WriteFile(
		script,
		[]byte(body),
		0o755,
	); err != nil { //nolint:gosec // it must be executable by the console user
		t.Fatal(err)
	}
	t.Setenv(sessionExecEnv, "1")
	sess := &session.Session{ID: "console", User: u.Username, UID: st.Uid}
	tgt, err := newTarget(layout.Resolve(t.TempDir()), testManifest(), sess)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd, err := tgt.buildCmd(script, nil, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	uid, gid := strconv.FormatUint(
		uint64(tgt.drop.uid),
		10,
	), strconv.FormatUint(
		uint64(tgt.drop.gid),
		10,
	)
	if len(lines) != 6 || lines[0] != uid || lines[1] != uid || lines[2] != gid || lines[3] != gid {
		t.Fatalf("identity:\n%s\n%s", stdout.String(), stderr.String())
	}
	got := strings.Fields(lines[4])
	want := strings.Split(groupList(tgt.drop), ",")
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || slices.Contains(got, "0") {
		t.Fatalf("groups %v, want %v", got, want)
	}
	if lines[5] != "Aqua" {
		t.Fatalf("bootstrap %q, want the user's Aqua session", lines[5])
	}
	t.Logf("dropped to %s: %s", u.Username, strings.Join(lines, " | "))
}
