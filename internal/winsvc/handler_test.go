package winsvc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu sync.Mutex
	st []Status
	ch chan Status
}

func newRecorder() *recorder { return &recorder{ch: make(chan Status, 256)} }

func (r *recorder) report(s Status) {
	r.mu.Lock()
	r.st = append(r.st, s)
	r.mu.Unlock()
	r.ch <- s
}

func (r *recorder) waitFor(t *testing.T, want State) Status {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case s := <-r.ch:
			if s.State == want {
				return s
			}
		case <-timeout:
			t.Fatalf("never reported %s", want)
		}
	}
}

func (r *recorder) all() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Status(nil), r.st...)
}

// A stop request cancels the body exactly once, reports StopPending with a
// checkpoint that advances while the body drains, then Stopped with no
// error — the shape the SCM needs to not declare the service hung.
func TestServeStopDrainsWithAdvancingCheckpoint(t *testing.T) {
	for _, c := range []Control{ControlStop, ControlShutdown, ControlPreShutdown} {
		rec := newRecorder()
		ctrl := make(chan Control, 4)
		release := make(chan struct{})
		cancelled := make(chan struct{})
		body := func(ctx context.Context) error {
			<-ctx.Done()
			close(cancelled)
			<-release // core still draining
			return nil
		}
		done := make(chan error, 1)
		go func() { done <- Serve(ctrl, rec.report, body, 5*time.Millisecond) }()

		running := rec.waitFor(t, Running)
		if running.Accepts != AcceptStop|AcceptPreShutdown {
			t.Fatalf("accepts %#x", running.Accepts)
		}
		ctrl <- ControlInterrogate
		if s := rec.waitFor(t, Running); s != running {
			t.Fatalf("interrogate reported %+v", s)
		}
		ctrl <- c
		<-cancelled
		first := rec.waitFor(t, StopPending)
		if first.WaitHint <= 0 || first.Accepts != 0 {
			t.Fatalf("stop-pending %+v", first)
		}
		ctrl <- c // a repeated stop is ignored, not a second cancel
		next := rec.waitFor(t, StopPending)
		if next.CheckPoint <= first.CheckPoint {
			t.Fatalf("checkpoint did not advance: %d then %d", first.CheckPoint, next.CheckPoint)
		}
		close(release)
		final := rec.waitFor(t, Stopped)
		if err := <-done; err != nil {
			t.Fatalf("control %d: Serve = %v", c, err)
		}
		if final.Win32ExitCode != 0 {
			t.Fatalf("clean stop reported exit %d", final.Win32ExitCode)
		}
		if got := rec.all()[0]; got.State != StartPending {
			t.Fatalf("first report %+v, want start-pending", got)
		}
	}
}

// A body that fails, or returns without being asked, must stop with a
// service-specific error so the SCM's recovery actions restart it.
func TestServeFailureIsReportedForRecovery(t *testing.T) {
	for name, bodyErr := range map[string]error{"error": errBoom, "unasked": nil} {
		rec := newRecorder()
		err := Serve(
			make(chan Control),
			rec.report,
			func(context.Context) error { return bodyErr },
			time.Second,
		)
		want := bodyErr
		if want == nil {
			want = ErrUnexpectedExit
		}
		if !errors.Is(err, want) {
			t.Fatalf("%s: Serve = %v", name, err)
		}
		all := rec.all()
		final := all[len(all)-1]
		if final.State != Stopped || final.Win32ExitCode != errorServiceSpecific ||
			final.ServiceExitCode == 0 {
			t.Fatalf("%s: final %+v", name, final)
		}
	}
}

// A body failing during a stop is still a failure.
func TestServeErrorDuringStop(t *testing.T) {
	rec := newRecorder()
	ctrl := make(chan Control, 1)
	ctrl <- ControlStop
	err := Serve(ctrl, rec.report, func(ctx context.Context) error {
		<-ctx.Done()
		return errBoom
	}, time.Second)
	if !errors.Is(err, errBoom) {
		t.Fatalf("Serve = %v", err)
	}
	if all := rec.all(); all[len(all)-1].Win32ExitCode != errorServiceSpecific {
		t.Fatalf("final %+v", all[len(all)-1])
	}
}
