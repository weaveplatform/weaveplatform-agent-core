//go:build linux

package supervise

import "syscall"

// setPdeathsig asks the kernel to SIGKILL the module when its parent (core)
// dies — the unix half of "modules die with core". Linux only; macOS has
// no equivalent and relies on the SDK host-connection watchdog.
func setPdeathsig(a *syscall.SysProcAttr) {
	a.Pdeathsig = syscall.SIGKILL
}
