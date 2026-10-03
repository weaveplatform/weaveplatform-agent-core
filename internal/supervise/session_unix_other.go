//go:build !windows && !darwin

package supervise

import (
	"os/exec"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// sessionCommand is a plain exec on Linux: the session is reached through
// what logind recorded — uid/gid/groups via SysProcAttr.Credential, and
// XDG_RUNTIME_DIR, WAYLAND_DISPLAY/DISPLAY and DBUS_SESSION_BUS_ADDRESS in
// the environment — not through any kernel session object. The process
// stays in core's cgroup rather than the session's scope, so logind's
// KillUserProcesses does not reach it; core stops it when the watcher sees
// the session end.
func sessionCommand(bin string, _ *session.Session, _ *creds) (*exec.Cmd, bool) {
	return exec.Command(bin), false //nolint:noctx // lifetime owned by the supervisor
}
