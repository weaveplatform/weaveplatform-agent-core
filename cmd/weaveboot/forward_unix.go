//go:build !windows

package main

import (
	"os"
	"syscall"
)

// forwardSignals are passed through to core rather than acted on: SIGHUP is
// systemd's ExecReload, which asks core to reread its modules.
var forwardSignals = []os.Signal{syscall.SIGHUP}
