package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads SO_PEERCRED from a Unix-domain connection.
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
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return
		}
		pc = PeerCred{UID: ucred.Uid, HasUID: true, PID: int(ucred.Pid), HasPID: true}
	})
	return pc
}
