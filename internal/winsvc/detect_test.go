package winsvc

import "testing"

func TestStartedBySCM(t *testing.T) {
	procs := []procEntry{
		{PID: 4, Parent: 0, Exe: "System"},
		{PID: 700, Parent: 600, Exe: "services.exe"},
		{PID: 800, Parent: 700, Exe: "weaveboot.exe"},
		{PID: 900, Parent: 650, Exe: "weaveboot.exe"},
		{PID: 650, Parent: 1, Exe: "cmd.exe"},
		{PID: 1000, Parent: 12345, Exe: "orphan.exe"},
	}
	for pid, want := range map[uint32]bool{
		800:  true,  // child of services.exe
		900:  false, // child of a shell
		1000: false, // parent gone
		4242: false, // not in the snapshot
	} {
		if got := startedBySCM(procs, pid); got != want {
			t.Errorf("pid %d: %v, want %v", pid, got, want)
		}
	}
	procs[1].Exe = "SERVICES.EXE"
	if !startedBySCM(procs, 800) {
		t.Fatal("image names are case-insensitive on Windows")
	}
}
