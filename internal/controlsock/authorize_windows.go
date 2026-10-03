package controlsock

import "github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"

// controlAuthorizer on Windows is allow-all here: the control pipe's
// restrictive SDDL (SYSTEM + Administrators, set by ipc) is the gate, since
// peer uid is not available via the net.Conn. See WINDOWS_HANDOFF.md.
func controlAuthorizer() ipc.Authorizer {
	return func(ipc.PeerCred) error { return nil }
}
