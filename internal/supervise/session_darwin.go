package supervise

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

const (
	launchctlPath = "/bin/launchctl"
	// ngroupsMax is NGROUPS_MAX: setgroups(2) refuses more, and the whole
	// launch would fail with it.
	ngroupsMax = 16
)

// selfExecutable locates the weave-agent binary that does the identity drop;
// a seam so tests need not be weave-agent.
var selfExecutable = os.Executable

// sessionCommand runs the module in the console user's GUI session.
//
// The pasteboard, and every other per-user GUI service, is a Mach service in
// the user's gui/<uid> launchd domain, reached through the bootstrap port a
// process inherits. core is a LaunchDaemon in the system domain, so a plain
// setuid child would be the right user in the wrong bootstrap: NSPasteboard
// finds no pasteboard server. `launchctl asuser <uid>` joins the user's audit
// session, moves onto their bootstrap and execs in place (the pid core holds
// stays the module's). Joining the audit session needs root — run as the
// user, launchctl fails with "Could not switch to audit session: Operation
// not permitted" — so SysProcAttr.Credential cannot do the drop: it would
// apply to launchctl itself. launchctl runs the next program as root, and
// that program drops.
//
// The dropper is weave-agent itself (SessionExec): it sets the user's groups,
// gid and uid, checks it cannot get root back, and execs the module, also in
// place. Nothing forks, so the process tree, stdout handshake, exit status
// and kill behave as for a direct child.
//
// Not chroot(8), which did this drop until macOS refused it: the kernel kills
// a hardened-runtime process exec'd under chroot ("AMFI: hardened runtime not
// allowed in chroot"), and notarisation requires the hardened runtime, so
// every signed session module died before its handshake. Not a separate
// helper binary: weaveboot updates core by replacing weave-agent alone, so a
// helper beside it would drift from the core that calls it, and weave-agent
// is already signed, hardened and notarised. Not a drop inside the module: a
// module is third-party code, and core does not hand it root on trust that
// it will let go.
//
// Not a LaunchAgent bootstrapped into gui/<uid>: launchd would own the
// process, so core would lose the stdout handshake, the exit status it
// classifies (78 = protocol refusal) and the kill on shutdown — and would be
// writing plists into a user's domain to get a process it then cannot see.
// Not posix_spawn with the user's audit session either: joining a session is
// private SPI (audit_session_join on a port core would first have to fetch
// from launchd), where launchctl asuser is the supported way to do the same.
//
// Without a drop (core is not root and already is this user) the launchctl
// step alone puts the module in the GUI bootstrap.
func sessionCommand(bin string, sess *session.Session, drop *creds) (*exec.Cmd, bool, error) {
	uid := strconv.FormatUint(uint64(sess.UID), 10)
	if drop == nil {
		//nolint:noctx // the supervisor owns the module's lifetime and stops it itself
		return exec.Command(launchctlPath, "asuser", uid, bin), false, nil
	}
	self, err := selfExecutable()
	if err != nil {
		return nil, false, fmt.Errorf("locating weave-agent to drop to uid %d: %w", drop.uid, err)
	}
	//nolint:noctx // the supervisor owns the module's lifetime and stops it itself
	return exec.Command(launchctlPath, "asuser", uid, self, SessionExecCommand,
		strconv.FormatUint(uint64(drop.uid), 10),
		strconv.FormatUint(uint64(drop.gid), 10),
		groupList(drop), bin), true, nil
}

// groupList is the supplementary group list SessionExec sets: primary group
// first, then the rest, capped at ngroupsMax. setgroups(2) leaves the
// credential with no group-membership uid, so membership past the cap is not
// resolved dynamically; the cap is what a setgroups caller gets.
func groupList(c *creds) string {
	gs := []string{strconv.FormatUint(uint64(c.gid), 10)}
	for _, g := range c.groups {
		if g == c.gid {
			continue
		}
		if len(gs) == ngroupsMax {
			break
		}
		gs = append(gs, strconv.FormatUint(uint64(g), 10))
	}
	return strings.Join(gs, ",")
}
