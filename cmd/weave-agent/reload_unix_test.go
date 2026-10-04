//go:build !windows

package main

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/core"
)

// SIGHUP becomes a reload request, and does not take its default action of
// killing the process.
func TestSIGHUPRequestsReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload := notifyReload(ctx)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reload:
	case <-time.After(10 * time.Second):
		t.Fatal("SIGHUP did not reach the reload channel")
	}
}

// The reload channel reaches core.
func TestReloadReachesCore(t *testing.T) {
	clearEnv(t)
	var got core.Options
	stubCore(t, func(_ context.Context, o core.Options) error { got = o; return nil })
	if code := run(nil, &discard{}, &discard{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got.Reload == nil {
		t.Fatal("core started without a reload channel")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
