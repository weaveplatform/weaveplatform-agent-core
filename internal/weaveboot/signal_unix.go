//go:build !windows

package weaveboot

import (
	"os"
	"os/exec"
	"syscall"
)

// terminateSignal asks core to shut down gracefully.
var terminateSignal os.Signal = syscall.SIGTERM

func gracefulStop(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return cmd.Process.Signal(terminateSignal) }
}
