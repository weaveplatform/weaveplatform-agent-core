package winsvc

import (
	"context"
	"errors"
	"time"
)

// State is a service's current state; the values are the SCM's
// SERVICE_STATUS dwCurrentState codes.
type State uint32

// Service states.
const (
	Stopped         State = 1
	StartPending    State = 2
	StopPending     State = 3
	Running         State = 4
	ContinuePending State = 5
	PausePending    State = 6
	Paused          State = 7
)

func (s State) String() string {
	switch s {
	case Stopped:
		return "stopped"
	case StartPending:
		return "start-pending"
	case StopPending:
		return "stop-pending"
	case Running:
		return "running"
	case ContinuePending:
		return "continue-pending"
	case PausePending:
		return "pause-pending"
	case Paused:
		return "paused"
	}
	return "unknown"
}

// Control is a request the SCM delivers to the service's handler; the
// values are the SERVICE_CONTROL_* codes.
type Control uint32

// Controls the agent acts on.
const (
	ControlStop        Control = 1
	ControlInterrogate Control = 4
	ControlShutdown    Control = 5
	ControlPreShutdown Control = 15
)

// Accepted-control bits (SERVICE_ACCEPT_*).
const (
	AcceptStop        uint32 = 0x1
	AcceptShutdown    uint32 = 0x4
	AcceptPreShutdown uint32 = 0x100
)

// Status is what the service reports to the SCM.
type Status struct {
	State           State
	Accepts         uint32
	CheckPoint      uint32
	WaitHint        time.Duration
	Win32ExitCode   uint32
	ServiceExitCode uint32
}

// errorServiceSpecific is ERROR_SERVICE_SPECIFIC_ERROR: the SCM then reads
// ServiceExitCode, and — because Install sets FailureActionsOnNonCrashFailures
// — counts the stop as a failure and applies the restart action.
const errorServiceSpecific = 1066

// ErrUnexpectedExit is the error Serve reports when the body returns before
// any stop was requested. weaveboot only returns on cancellation, so this
// means it gave up; reporting it as a failure is what makes the SCM restart
// it, the equivalent of systemd's Restart=always.
var ErrUnexpectedExit = errors.New("winsvc: service body exited without a stop request")

const (
	startWaitHint = 10 * time.Second
	// stopWaitHint must outlast one checkpoint tick by a margin: the SCM
	// treats a checkpoint that has not advanced within the hint as a hung
	// service.
	stopWaitHint = 10 * time.Second
)

// Serve runs body as a service. It reports StartPending, then Running; on
// Stop, Shutdown or PreShutdown it cancels body's context — the same path a
// SIGTERM takes on unix — and reports StopPending with an advancing
// checkpoint every tick until body returns; then Stopped. A body error, or a
// body that returns unasked, is reported as a service-specific failure.
//
// report must not block for long: it is SetServiceStatus in production.
func Serve(
	ctrl <-chan Control,
	report func(Status),
	body func(context.Context) error,
	tick time.Duration,
) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	report(Status{State: StartPending, WaitHint: startWaitHint})
	done := make(chan error, 1)
	go func() { done <- body(ctx) }()

	// PreShutdown rather than Shutdown: a service accepting only Shutdown
	// gets about five seconds at system shutdown, too little for core to
	// drain its modules and close the store. Accepting PreShutdown gives the
	// configured PreshutdownTimeout and makes the SCM skip Shutdown.
	cur := Status{State: Running, Accepts: AcceptStop | AcceptPreShutdown}
	report(cur)

	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	var tickC <-chan time.Time
	for {
		select {
		case c := <-ctrl:
			switch c {
			case ControlInterrogate:
				report(cur)
			case ControlStop, ControlShutdown, ControlPreShutdown:
				if cur.State == StopPending {
					continue
				}
				cancel()
				cur = Status{State: StopPending, CheckPoint: 1, WaitHint: stopWaitHint}
				report(cur)
				ticker = time.NewTicker(tick)
				tickC = ticker.C
			}
		case <-tickC:
			cur.CheckPoint++
			report(cur)
		case err := <-done:
			if err == nil && cur.State != StopPending {
				err = ErrUnexpectedExit
			}
			final := Status{State: Stopped}
			if err != nil {
				final.Win32ExitCode = errorServiceSpecific
				final.ServiceExitCode = 1
			}
			report(final)
			return err
		}
	}
}
