package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads LOCAL_PEERCRED (the process's effective uid) from a
// Unix-domain connection on macOS. PID is not available via this path.
func peerCred(c net.Conn) PeerCred {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return PeerCred{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerCred{}
	}
	var pc PeerCred
	_ = raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return
		}
		pc = PeerCred{UID: ucred.Uid, HasUID: true}
	})
	return pc
}
