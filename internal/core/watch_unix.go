//go:build linux || darwin

package core

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// watchRetry is how long the watch waits before trying again when the modules
// directory is missing or the watch fails; the periodic rescan covers the gap.
// Atomic because a test shortens it while an earlier test's core may still be
// watching.
var watchRetry = func() *atomic.Int64 {
	var d atomic.Int64
	d.Store(int64(5 * time.Second))
	return &d
}()

var errWatchRootGone = errors.New("modules directory removed or moved")

// watchModules calls notify for every change the platform watch (inotify on
// Linux, kqueue on macOS) reports in dir or in any module directory directly
// under it, until ctx ends. notify is the reload trigger, which debounces: a
// package install's burst of events is one pass.
func watchModules(ctx context.Context, log *slog.Logger, dir string, notify func()) {
	logged := false
	for ctx.Err() == nil {
		err := watchOnce(ctx, dir, notify)
		if ctx.Err() != nil {
			return
		}
		// Whatever ended the watch may itself be a change (the directory
		// went away, or came back).
		notify()
		if !logged {
			log.Warn("module directory watch unavailable; retrying", "dir", dir, "err", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(watchRetry.Load())):
		}
	}
}
