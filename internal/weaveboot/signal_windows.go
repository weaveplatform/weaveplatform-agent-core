package weaveboot

import (
	"os/exec"
	"sync"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/console"
)

// Windows has no SIGTERM. The nearest thing a Go process can catch is a
// console control event, which its runtime delivers as os.Interrupt — the
// signal core already handles. So core is started in its own process group,
// and stop sends CTRL_BREAK to that group alone (CTRL_C cannot be aimed at
// a group). That needs a console shared with core: a service has none, so
// one is allocated — in session 0 it is never shown. Allocation fails
// harmlessly when weaveboot already has a console.
//
// The group is core's and everything core starts, so modules receive the
// break at the same moment core does — the race the Linux unit avoids with
// KillMode=mixed. Starting modules in groups of their own is
// internal/supervise's to change; until then a module may exit before core
// asks it to, and core logs that shutdown as untidy.
var (
	consoleOnce  sync.Once
	allocConsole = console.AllocConsole
	ctrlBreak    = func(pid uint32) error {
		return console.GenerateConsoleCtrlEvent(console.CTRL_BREAK_EVENT, pid)
	}
)

func gracefulStop(cmd *exec.Cmd) {
	consoleOnce.Do(func() { _ = allocConsole() })
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
	cmd.Cancel = func() error {
		// A process group's id is its leader's pid.
		pid := uint32(cmd.Process.Pid) //nolint:gosec // G115: a Windows pid is a DWORD
		if err := ctrlBreak(pid); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
