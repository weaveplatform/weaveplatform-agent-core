package ipc

import "net"

// peerCred on Windows returns no uid: named-pipe access is gated by the
// pipe's security descriptor (SDDL), not a uid check here. The connecting
// process id is obtainable via GetNamedPipeClientProcessId on the pipe
// handle, but go-winio does not expose the handle on the net.Conn; if
// per-peer PID checks are needed, that plumbing (or a WTS session check)
// is the Windows follow-up. See WINDOWS_HANDOFF.md.
func peerCred(_ net.Conn) PeerCred { return PeerCred{} }
