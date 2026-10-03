package winsvc

import "strings"

// procEntry is one row of a process snapshot.
type procEntry struct {
	PID, Parent uint32
	Exe         string
}

// startedBySCM reports whether pid's parent is services.exe. Together with
// session 0 this is the test x/sys/windows/svc.IsWindowsService settled on:
// session 0 alone also matches anything SYSTEM launches at boot (a
// specialize-pass script, a scheduled task), and those must run weaveboot
// interactively, not hang waiting for an SCM that never calls back.
func startedBySCM(procs []procEntry, pid uint32) bool {
	var parent uint32
	found := false
	for _, p := range procs {
		if p.PID == pid {
			parent, found = p.Parent, true
			break
		}
	}
	if !found {
		return false
	}
	for _, p := range procs {
		if p.PID == parent {
			return strings.EqualFold(p.Exe, "services.exe")
		}
	}
	return false
}
