package supervise

import "io"

// SessionExecCommand, as weave-agent's first argument, makes it the identity
// drop of a macOS session launch rather than core (sessionCommand in
// session_darwin.go says why). Core passes it; nothing else should.
const SessionExecCommand = "session-exec"

// SessionExec is weave-agent's session-exec mode: args are uid, gid, a
// comma-separated group list and the module binary. It drops to that identity
// and execs the binary in place, so it returns only on failure, with the exit
// status weave-agent should end with.
func SessionExec(args []string, stderr io.Writer) int {
	return sessionExec(args, stderr)
}
