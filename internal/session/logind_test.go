package session

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// logindRoot builds a fake filesystem root holding logind state files.
type logindRoot struct {
	t    *testing.T
	root string
}

func newLogindRoot(t *testing.T) *logindRoot {
	t.Helper()
	// Not t.TempDir(): unix socket paths must fit sun_path (104 bytes on
	// macOS) and test names are long.
	dir, err := os.MkdirTemp("", "ld-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return &logindRoot{t: t, root: dir}
}

func (r *logindRoot) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *logindRoot) socket(rel string) {
	r.t.Helper()
	if runtime.GOOS == "windows" {
		r.t.Skip("logind fixtures need unix sockets; the parser is covered on unix")
	}
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		r.t.Fatal(err)
	}
	l, err := net.Listen("unix", p)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { l.Close() })
}

const aliceWayland = `# This is private data. Do not parse.
UID=1000
USER=alice
ACTIVE=1
STATE=active
REMOTE=0
TYPE=wayland
CLASS=user
SEAT=seat0
`

func TestLogindActiveWaylandSession(t *testing.T) {
	r := newLogindRoot(t)
	r.write(
		"run/systemd/seats/seat0",
		"# private\nIS_SEAT0=1\nACTIVE=2\nACTIVE_UID=1000\nmalformed line\n",
	)
	r.write("run/systemd/sessions/2", aliceWayland)
	r.write("run/systemd/users/1000", "RUNTIME=/run/user/1000\n")
	r.socket("run/user/1000/wayland-1")
	r.socket("run/user/1000/wayland-0")
	r.write("run/user/1000/wayland-0.lock", "")
	r.write("run/user/1000/wayland-9", "") // a plain file is not a compositor
	r.socket("run/user/1000/bus")

	s, ok, err := Logind{Root: r.root}.Console()
	if err != nil || !ok {
		t.Fatalf("Console = ok=%v err=%v", ok, err)
	}
	if s.ID != "2" || s.User != "alice" || s.UID != 1000 {
		t.Fatalf("session = %+v", s)
	}
	want := []string{
		"XDG_SESSION_ID=2", "XDG_SEAT=seat0", "XDG_SESSION_TYPE=wayland",
		"XDG_RUNTIME_DIR=/run/user/1000", "WAYLAND_DISPLAY=wayland-0",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
	}
	if !slices.Equal(s.Env, want) {
		t.Fatalf("env =\n%s\nwant\n%s", strings.Join(s.Env, "\n"), strings.Join(want, "\n"))
	}
}

// An X11 session gets the DISPLAY logind recorded; without a users file the
// runtime dir is the conventional one, and absent sockets add nothing.
func TestLogindX11Session(t *testing.T) {
	r := newLogindRoot(t)
	r.write("run/systemd/seats/seat1", "ACTIVE=c4\n")
	r.write(
		"run/systemd/sessions/c4",
		"UID=1001\nUSER=bob\nSTATE=active\nCLASS=user\nTYPE=x11\nDISPLAY=:0\n",
	)
	if err := os.MkdirAll(filepath.Join(r.root, "run/user/1001"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, ok, err := Logind{Root: r.root, Seat: "seat1"}.Console()
	if err != nil || !ok {
		t.Fatalf("Console = ok=%v err=%v", ok, err)
	}
	want := []string{
		"XDG_SESSION_ID=c4",
		"XDG_SEAT=seat1",
		"XDG_SESSION_TYPE=x11",
		"XDG_RUNTIME_DIR=/run/user/1001",
		"DISPLAY=:0",
	}
	if !slices.Equal(s.Env, want) {
		t.Fatalf("env = %q, want %q", s.Env, want)
	}
}

func TestLogindNoRuntimeDir(t *testing.T) {
	r := newLogindRoot(t)
	r.write("run/systemd/seats/seat0", "ACTIVE=3\n")
	r.write("run/systemd/sessions/3", "UID=1002\nUSER=carol\nSTATE=active\nCLASS=user\n")
	s, ok, err := Logind{Root: r.root}.Console()
	if err != nil || !ok {
		t.Fatalf("Console = ok=%v err=%v", ok, err)
	}
	if want := []string{"XDG_SESSION_ID=3", "XDG_SEAT=seat0"}; !slices.Equal(s.Env, want) {
		t.Fatalf("env = %q, want %q", s.Env, want)
	}
}

// Everything that is not a local user actively at seat0 is "nobody".
func TestLogindNoConsoleUser(t *testing.T) {
	cases := map[string]struct{ seat, session string }{
		"no logind":         {"", ""},
		"no active session": {"IS_SEAT0=1\n", ""},
		"path in ACTIVE":    {"ACTIVE=../x\n", ""},
		"dotdot ACTIVE":     {"ACTIVE=..\n", ""},
		"session vanished":  {"ACTIVE=2\n", ""},
		"greeter":           {"ACTIVE=2\n", "UID=120\nUSER=gdm\nSTATE=active\nCLASS=greeter\n"},
		"switched away":     {"ACTIVE=2\n", "UID=1000\nUSER=alice\nSTATE=online\nCLASS=user\n"},
		"remote": {
			"ACTIVE=2\n",
			"UID=1000\nUSER=alice\nSTATE=active\nCLASS=user\nREMOTE=1\n",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newLogindRoot(t)
			if c.seat != "" {
				r.write("run/systemd/seats/seat0", c.seat)
			}
			if c.session != "" {
				r.write("run/systemd/sessions/2", c.session)
			}
			if s, ok, err := (Logind{Root: r.root}).Console(); ok || err != nil {
				t.Fatalf("Console = %+v ok=%v err=%v", s, ok, err)
			}
		})
	}
}

func TestLogindMalformed(t *testing.T) {
	cases := map[string]string{
		"bad uid": "UID=alice\nUSER=alice\nSTATE=active\nCLASS=user\n",
		"no user": "UID=1000\nSTATE=active\nCLASS=user\n",
	}
	for name, sess := range cases {
		t.Run(name, func(t *testing.T) {
			r := newLogindRoot(t)
			r.write("run/systemd/seats/seat0", "ACTIVE=2\n")
			r.write("run/systemd/sessions/2", sess)
			if _, ok, err := (Logind{Root: r.root}).Console(); ok || err == nil {
				t.Fatalf("malformed session accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

// A state file that exists but cannot be read is a probe failure, not
// "nobody home".
func TestLogindUnreadable(t *testing.T) {
	for _, which := range []string{"seat", "session"} {
		t.Run(which, func(t *testing.T) {
			r := newLogindRoot(t)
			r.write("run/systemd/seats/seat0", "ACTIVE=2\n")
			r.write("run/systemd/sessions/2", aliceWayland)
			// A directory where the file should be fails the read on every OS
			// and for every uid, root included.
			target := "run/systemd/seats/seat0"
			if which == "session" {
				target = "run/systemd/sessions/2"
			}
			p := filepath.Join(r.root, target)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := (Logind{Root: r.root}).Console(); ok || err == nil {
				t.Fatalf("unreadable %s: ok=%v err=%v", which, ok, err)
			}
		})
	}
}

func TestLogindDefaultRoot(t *testing.T) {
	if got := (Logind{}).path("run"); got != filepath.Join("/", "run") {
		t.Fatalf("path = %q", got)
	}
	if waylandSocket(filepath.Join(os.TempDir(), "definitely-absent-dir")) != "" {
		t.Fatal("wayland socket found in a missing dir")
	}
}
