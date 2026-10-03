package supervise

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

const (
	launchctlPath = "/bin/launchctl"
	chrootPath    = "/usr/sbin/chroot"
	// ngroupsMax is NGROUPS_MAX: setgroups(2) refuses more, and chroot -G
	// would fail the whole launch. Membership past it resolves dynamically
	// through opendirectoryd anyway.
	ngroupsMax = 16
)

// sessionCommand runs the module in the console user's GUI session.
//
// The pasteboard, and every other per-user GUI service, is a Mach service in
// the user's gui/<uid> launchd domain, reached through the bootstrap port a
// process inherits. core is a LaunchDaemon in the system domain, so a plain
// setuid child would be the right user in the wrong bootstrap: NSPasteboard
// finds no pasteboard server. `launchctl asuser <uid>` re-parents onto the
// user's bootstrap and execs in place (the pid core holds stays the module's);
// it runs the next program as root, so chroot(8) — `-u -g -G` then exec, also
// in place — drops to the user's ids, with chroot("/") a no-op. Both are SIP-
// protected system binaries and neither forks, so the process tree, stdout
// handshake, exit status and kill all behave as for a direct child.
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
// step alone puts the module in the GUI bootstrap; no chroot is needed or
// permitted.
func sessionCommand(bin string, sess *session.Session, drop *creds) (*exec.Cmd, bool) {
	uid := strconv.FormatUint(uint64(sess.UID), 10)
	if drop == nil {
		//nolint:noctx // the supervisor owns the module's lifetime and stops it itself
		return exec.Command(launchctlPath, "asuser", uid, bin), false
	}
	args := []string{
		"asuser", uid, chrootPath,
		"-u", strconv.FormatUint(uint64(drop.uid), 10),
		"-g", strconv.FormatUint(uint64(drop.gid), 10),
	}
	if gs := groupList(drop); gs != "" {
		args = append(args, "-G", gs)
	}
	args = append(args, "/", bin)
	//nolint:noctx // the supervisor owns the module's lifetime and stops it itself
	return exec.Command(launchctlPath, args...), true
}

// groupList is the -G argument: primary group first, then the rest, capped
// at ngroupsMax.
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
