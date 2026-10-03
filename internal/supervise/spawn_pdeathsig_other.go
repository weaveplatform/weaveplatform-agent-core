//go:build !linux && !windows

package supervise

import "syscall"

// setPdeathsig is a no-op on non-Linux unix (macOS has no parent-death
// signal). Orphan death there is enforced by the SDK's host-connection
// watchdog, which exits the module when its core connection drops.
func setPdeathsig(_ *syscall.SysProcAttr) {}
