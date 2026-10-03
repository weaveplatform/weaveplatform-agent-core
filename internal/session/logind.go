package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Errors for a session file that does not describe a usable session.
var (
	errBadUID = errors.New("bad UID")
	errNoUser = errors.New("no USER")
)

// Logind reads systemd-logind's state files under /run/systemd: the seat
// file names the active session, the session file says whose it is and what
// kind.
//
// The files, not org.freedesktop.login1 over D-Bus: they hold the same data
// logind serves (it writes them on every change), reading them needs no
// D-Bus client in core, and a fake is a directory of text files. systemd
// marks them "private, do not parse"; the keys used here (ACTIVE, UID, USER,
// STATE, CLASS, REMOTE, TYPE, DISPLAY, RUNTIME) have been stable since logind
// shipped, and a format change would surface as "no session", not as a
// module started in the wrong place.
type Logind struct {
	// Root is the filesystem root the state paths are resolved under; "/" in
	// production, a fixture directory in tests.
	Root string
	// Seat is the seat whose active session counts as the console; "seat0"
	// when empty — the only seat with a physical console.
	Seat string
}

// Console implements Source.
func (l Logind) Console() (Session, bool, error) {
	seat := l.Seat
	if seat == "" {
		seat = "seat0"
	}
	seatVars, err := readEnvFile(l.path("run/systemd/seats", seat))
	if errors.Is(err, fs.ErrNotExist) {
		// No logind, or no seat0 (a server or container): nobody can be
		// at a console that does not exist.
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	id := seatVars["ACTIVE"]
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." {
		return Session{}, false, nil
	}
	sv, err := readEnvFile(l.path("run/systemd/sessions", id))
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, false, nil // ended between the two reads
	}
	if err != nil {
		return Session{}, false, err
	}
	// A greeter (gdm, sddm) is a session on seat0 too, owned by a display-
	// manager account; it is the login screen, not a user.
	if sv["CLASS"] != "user" || sv["STATE"] != "active" || sv["REMOTE"] == "1" {
		return Session{}, false, nil
	}
	uid, err := strconv.ParseUint(sv["UID"], 10, 32)
	if err != nil {
		return Session{}, false, fmt.Errorf("logind session %s: %w %q", id, errBadUID, sv["UID"])
	}
	s := Session{ID: id, User: sv["USER"], UID: uint32(uid)}
	if s.User == "" {
		return Session{}, false, fmt.Errorf("logind session %s: %w", id, errNoUser)
	}
	s.Env = l.sessionEnv(id, seat, uint32(uid), sv)
	return s, true, nil
}

// sessionEnv is what a GUI process started outside the session would
// otherwise lack. Nothing here is guessed: each variable is set only when the
// thing it points at exists.
func (l Logind) sessionEnv(id, seat string, uid uint32, sv map[string]string) []string {
	env := []string{"XDG_SESSION_ID=" + id, "XDG_SEAT=" + seat}
	if t := sv["TYPE"]; t != "" {
		env = append(env, "XDG_SESSION_TYPE="+t)
	}
	runtime := ""
	if uv, err := readEnvFile(
		l.path("run/systemd/users", strconv.FormatUint(uint64(uid), 10)),
	); err == nil {
		runtime = uv["RUNTIME"]
	}
	if runtime == "" {
		// A path for the module's environment, not a lookup on this host:
		// always slash-separated, whatever OS the code is tested on.
		runtime = path.Join("/run/user", strconv.FormatUint(uint64(uid), 10))
	}
	if fi, err := os.Stat(l.path(runtime)); err == nil && fi.IsDir() {
		env = append(env, "XDG_RUNTIME_DIR="+runtime)
		if w := waylandSocket(l.path(runtime)); w != "" {
			env = append(env, "WAYLAND_DISPLAY="+w)
		}
		if isSocket(l.path(runtime, "bus")) {
			env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+path.Join(runtime, "bus"))
		}
	}
	// logind records DISPLAY for X11 sessions only. A Wayland session's
	// XWayland display is not recorded anywhere core can read reliably, and
	// modules in such a session should be speaking Wayland anyway.
	if d := sv["DISPLAY"]; d != "" {
		env = append(env, "DISPLAY="+d)
	}
	return env
}

func (l Logind) path(elem ...string) string {
	root := l.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

// waylandSocket returns the compositor's socket name in a runtime dir: the
// lowest wayland-N, skipping the .lock files compositors keep beside them.
func waylandSocket(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "wayland-") && !strings.HasSuffix(n, ".lock") &&
			isSocket(filepath.Join(dir, n)) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&fs.ModeSocket != 0
}

// readEnvFile parses systemd's KEY=VALUE state-file format.
func readEnvFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out, nil
}
