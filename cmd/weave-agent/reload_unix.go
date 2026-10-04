//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// notifyReload turns SIGHUP into a module reload request until ctx ends.
// SIGHUP is what `systemctl reload weave-agent` sends (ExecReload), by way of
// weaveboot, which forwards it.
func notifyReload(ctx context.Context) <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	out := make(chan struct{}, 1)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}
