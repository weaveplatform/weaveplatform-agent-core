package weaveboot

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// CTRL_BREAK can only be aimed at a process group, so without its own group
// core would share weaveboot's and the break would hit weaveboot too.
func TestGracefulStopStartsCoreInItsOwnGroup(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	gracefulStop(cmd)
	if cmd.SysProcAttr == nil ||
		cmd.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatal("core is not started in a process group of its own")
	}
	if cmd.Cancel == nil {
		t.Fatal("no graceful cancel installed")
	}
}

// When the break cannot be delivered (no shared console), stop must fall
// back to killing core at once rather than waiting out WaitDelay with core
// still running.
func TestCtrlBreakFailureFallsBackToKill(t *testing.T) {
	orig := ctrlBreak
	ctrlBreak = func(uint32) error { return errors.New("no console") }
	t.Cleanup(func() { ctrlBreak = orig })

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "ping", "-n", "120", "127.0.0.1")
	gracefulStop(cmd)
	cmd.WaitDelay = time.Minute
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	cancel()
	_ = cmd.Wait()
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("core outlived a failed CTRL_BREAK by %s; the kill fallback did not run", d)
	}
}
