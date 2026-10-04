//go:build !windows

package supervise

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// jobHandle is Windows-only containment; a no-op here. Unix containment is
// Pdeathsig (Linux) plus the SDK's host-connection watchdog (all unix), so
// a module dies when core dies rather than orphaning.
type jobHandle struct{}

var (
	// errNotRoot: a non-root core asked to start a module in another
	// user's session.
	errNotRoot = errors.New("not root")
	// errPeerNotAuthorized: a host-socket peer with the wrong uid.
	errPeerNotAuthorized = errors.New("not authorized for module")
)

// Seams so tests can reach the root-only credential paths unprivileged.
var (
	geteuid      = os.Geteuid
	lookupUser   = user.Lookup
	lookupUserID = user.LookupId
	groupIDs     = (*user.User).GroupIds
)

// serviceAccount is the unprivileged account "service"-privilege modules
// run as when core is root: one shared account created by the installer
// (per-module accounts are an open item in docs/WINDOWS_HANDOFF.md).
func serviceAccount() string {
	if runtime.GOOS == "darwin" {
		return "_weaveagent"
	}
	return "weave-agent"
}

// creds is an identity a module runs as instead of core's own.
type creds struct {
	uid, gid uint32
	groups   []uint32
}

// target is where and as whom one launch runs.
type target struct {
	layout layout.Layout
	m      *manifest.Manifest
	sess   *session.Session
	// drop is the identity to switch to; nil runs the module as core.
	drop *creds
	// home is the session user's home directory; empty for system modules.
	home string
}

func newTarget(l layout.Layout, m *manifest.Manifest, sess *session.Session) (*target, error) {
	t := &target{layout: l, m: m, sess: sess}
	var err error
	if sess != nil {
		t.drop, t.home, err = sessionCreds(sess)
	} else {
		t.drop, err = systemCreds(m)
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// systemCreds resolves the identity a system-session module drops to. Nil
// when core is not root (dev runs) or the module is system-privilege — in
// both cases there is nothing to drop. It fails closed on a drop it cannot
// perform.
func systemCreds(m *manifest.Manifest) (*creds, error) {
	if geteuid() != 0 {
		return nil, nil //nolint:nilnil // nil creds is the documented "nothing to drop"
	}
	switch m.Privilege {
	case manifest.PrivilegeSystem:
		return nil, nil //nolint:nilnil // nil creds is the documented "nothing to drop"
	case manifest.PrivilegeService:
		u, err := lookupUser(serviceAccount())
		if err != nil {
			return nil, fmt.Errorf(
				"service account %q missing (installer creates it): %w",
				serviceAccount(),
				err,
			)
		}
		uid, gid, err := parseIDs(u)
		if err != nil {
			return nil, err
		}
		return &creds{uid: uid, gid: gid}, nil
	default:
		// placementError refuses this at Add; reaching here is a bug, and
		// the safe answer to a bug in privilege code is not to launch.
		return nil, fmt.Errorf("privilege %q %w", m.Privilege, errNoSystemIdentity)
	}
}

// sessionCreds resolves the console user a per-user module runs as. Root
// core drops to them; a non-root core can only start a module in its own
// session (a developer running core from their login), and refuses anyone
// else's rather than run the module as the wrong user.
func sessionCreds(sess *session.Session) (*creds, string, error) {
	u, err := lookupUserID(strconv.FormatUint(uint64(sess.UID), 10))
	if err != nil {
		return nil, "", fmt.Errorf("console user uid %d: %w", sess.UID, err)
	}
	uid, gid, err := parseIDs(u)
	if err != nil {
		return nil, "", err
	}
	euid := geteuid()
	switch {
	case euid == 0:
	case euid == int(uid):
		return nil, u.HomeDir, nil
	default:
		return nil, "", fmt.Errorf(
			"core runs as uid %d, %w: it cannot start a module in uid %d's session",
			euid, errNotRoot, uid,
		)
	}
	// Supplementary groups are set explicitly: left alone, the child keeps
	// root's (wheel, admin), which is exactly the residue a drop exists to
	// shed.
	gids, err := groupIDs(u)
	if err != nil {
		return nil, "", fmt.Errorf("groups of %s: %w", u.Username, err)
	}
	c := &creds{uid: uid, gid: gid}
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, "", fmt.Errorf("group id %q of %s: %w", g, u.Username, err)
		}
		c.groups = append(c.groups, uint32(n))
	}
	return c, u.HomeDir, nil
}

func parseIDs(u *user.User) (uid, gid uint32, err error) {
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("uid of %s: %w", u.Username, err)
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("gid of %s: %w", u.Username, err)
	}
	return uint32(uid64), uint32(gid64), nil
}

func (t *target) close() {}

// stageBinary returns the path to exec. A module that runs as someone else
// cannot reach its binary where it is installed: the state tree is 0700
// root. It gets a root-owned, read-only copy under the layout's ExecDir
// instead — root-owned so the user it runs as cannot swap it between
// verification and exec, which would hand them the module's host-service
// identity. ExecDir is under the state dir rather than the run dir because
// /run is noexec on most Linux distributions.
func (t *target) stageBinary(bin string) (string, error) {
	if t.drop == nil {
		return bin, nil
	}
	dir := t.layout.ModuleExecDir(t.m.ID)
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clearing staging dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating staging dir: %w", err)
	}
	// MkdirAll leaves an existing ExecDir as it was; it must be searchable,
	// and is no more than that, so no module can list another's copy.
	if err := os.Chmod(filepath.Dir(dir), 0o711); err != nil {
		return "", fmt.Errorf("opening staging dir: %w", err)
	}
	staged := filepath.Join(dir, filepath.Base(bin))
	if err := copyExecutable(bin, staged); err != nil {
		return "", err
	}
	return staged, nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening module binary: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555)
	if err != nil {
		return fmt.Errorf("creating staged binary: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copying module binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing staged binary: %w", err)
	}
	return nil
}

// prepareSocketDir makes a dropped module able to create its own listener
// in, and dial host.sock inside, the per-module socket dir. Core owns the
// dir 0700; without the chown a dropped module EACCESes. The run dir and
// run/modules above it become search-only for others (0711): a dropped
// module must traverse them to reach its own dir, while listing them — and
// every other module's socket dir, still 0700 — stays closed. (layout.Ensure
// already holds the run dir there; repeating it costs nothing.) No-op when
// not dropping.
func (t *target) prepareSocketDir(dir, hostAddr string) error {
	if t.drop == nil {
		return nil
	}
	for _, d := range []string{t.layout.RunDir, filepath.Dir(dir)} {
		if err := os.Chmod(d, 0o711); err != nil {
			return fmt.Errorf("opening %s for traversal: %w", d, err)
		}
	}
	if err := os.Chown(dir, int(t.drop.uid), int(t.drop.gid)); err != nil {
		return fmt.Errorf("chown module socket dir: %w", err)
	}
	if err := os.Chown(hostAddr, int(t.drop.uid), int(t.drop.gid)); err != nil {
		return fmt.Errorf("chown host socket: %w", err)
	}
	return nil
}

func (t *target) listenHost(ctx context.Context, addr string) (net.Listener, error) {
	l, err := ipc.ListenAuthorized(ctx, addr, t.authorizePeer())
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}
	return l, nil
}

// authorizePeer authorizes connections to a module's host socket by peer
// uid: root, core's own uid, or the uid the module runs as. This is the real
// defence the env token only imitated — a same-uid neighbour can read the
// token from /proc but cannot present a different uid to the kernel.
func (t *target) authorizePeer() ipc.Authorizer {
	allowed := map[uint32]bool{0: true}
	// A uid is a uint32 on every unix; the check keeps the conversion honest.
	if uid := os.Getuid(); uid >= 0 && uid <= math.MaxUint32 {
		allowed[uint32(uid)] = true
	}
	if t.drop != nil {
		allowed[t.drop.uid] = true
	}
	return func(p ipc.PeerCred) error {
		if !p.HasUID {
			return nil // can't determine on this platform; dir perms gate
		}
		if allowed[p.UID] {
			return nil
		}
		return fmt.Errorf("peer uid %d %w %s", p.UID, errPeerNotAuthorized, t.m.ID)
	}
}

// start spawns the module. Credentials and, on Linux, Pdeathsig ride
// SysProcAttr; a macOS session launch switches identity through launchctl
// instead (see sessionCommand).
func (t *target) start(bin string, extra []string, stdout, stderr io.Writer) (*child, error) {
	cmd := t.buildCmd(bin, extra, stdout, stderr)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return commandChild(cmd), nil
}

func (t *target) buildCmd(bin string, extra []string, stdout, stderr io.Writer) *exec.Cmd {
	cmd, viaLauncher := t.command(bin)
	cmd.Env = t.env(extra)
	if t.home != "" {
		if fi, err := os.Stat(t.home); err == nil && fi.IsDir() {
			cmd.Dir = t.home
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	setPdeathsig(cmd.SysProcAttr)
	if t.drop != nil && !viaLauncher {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: t.drop.uid, Gid: t.drop.gid, Groups: t.drop.groups,
		}
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd
}

// command builds the exec. viaLauncher reports that the command switches
// identity itself, so SysProcAttr must not.
func (t *target) command(bin string) (cmd *exec.Cmd, viaLauncher bool) {
	if t.sess == nil {
		// The supervisor owns the module's lifetime and stops it itself; a
		// context-bound Cmd would kill the module when a context ended.
		return exec.Command(bin), false //nolint:noctx // lifetime owned by the supervisor
	}
	return sessionCommand(bin, t.sess, t.drop)
}

// sessionOwnedEnv names variables that describe whoever started core —
// root's HOME, a daemon's TMPDIR, the service's own XDG session — and would
// be wrong inside a user's session. A per-user module gets the session's
// values or none.
var sessionOwnedEnv = []string{
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"MAIL",
	"TMPDIR",
	"XDG_RUNTIME_DIR",
	"XDG_SESSION_ID",
	"XDG_SESSION_TYPE",
	"XDG_SESSION_CLASS",
	"XDG_SEAT",
	"XDG_VTNR",
	"WAYLAND_DISPLAY",
	"DISPLAY",
	"XAUTHORITY",
	"DBUS_SESSION_BUS_ADDRESS",
}

// env is core's environment with the session user's identity and session
// variables in place of core's own, plus the handshake variables.
func (t *target) env(extra []string) []string {
	if t.sess == nil {
		return append(os.Environ(), extra...)
	}
	sessEnv := []string{"USER=" + t.sess.User, "LOGNAME=" + t.sess.User}
	if t.home != "" {
		sessEnv = append(sessEnv, "HOME="+t.home)
	}
	return mergeEnv(os.Environ(), sessionOwnedEnv, sessEnv, t.sess.Env, extra)
}

func postSpawn(int) (jobHandle, error) { return jobHandle{}, nil }

func killProc(c *child, _ jobHandle) {
	_ = c.kill()
}

func closeJob(_ jobHandle) {}
