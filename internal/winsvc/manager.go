package winsvc

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors the Manager implementations map SCM codes onto, so the
// operations below can be idempotent without knowing Win32 error numbers.
var (
	ErrNotInstalled   = errors.New("winsvc: service is not installed")
	ErrNotActive      = errors.New("winsvc: service is not running")
	ErrAlreadyRunning = errors.New("winsvc: service is already running")
	ErrUnsupported    = errors.New("winsvc: Windows services are only available on Windows")
	// ErrNotService is Run's answer when the process was not started by the
	// SCM after all; the caller then runs interactively.
	ErrNotService = errors.New("winsvc: process was not started by the service control manager")
	// ErrStartFailed: the service reached Stopped while being started.
	ErrStartFailed = errors.New("winsvc: service stopped while starting")
	// ErrTimeout: the service did not reach the wanted state in time.
	ErrTimeout = errors.New("winsvc: timed out waiting for the service")
)

// Manager is the SCM seam. The real one is NewManager on Windows; tests use
// a fake, which is why install, idempotency and the stop/start waits are
// testable on every OS.
type Manager interface {
	// Open returns ErrNotInstalled when the service does not exist.
	Open(name string) (Service, error)
	Create(c Config) (Service, error)
	Close() error
}

// Service is one opened service.
type Service interface {
	// Configure applies the whole of c — base config, description, recovery,
	// preshutdown budget and environment — to the existing service.
	Configure(c Config) error
	State() (State, error)
	Start() error
	// Stop sends SERVICE_CONTROL_STOP; ErrNotActive when not running.
	Stop() error
	Delete() error
	Close() error
}

// Waits bounds how long the operations below poll for a state change.
type Waits struct {
	Poll    time.Duration
	Timeout time.Duration
}

// DefaultWaits outlasts weaveboot's own 15s drain of core plus the SCM's
// process teardown.
var DefaultWaits = Waits{Poll: 250 * time.Millisecond, Timeout: 45 * time.Second}

// Install creates the service, or reconfigures it in place when it already
// exists. It reports whether the service was created.
func Install(m Manager, c Config) (created bool, err error) {
	if err := c.Validate(); err != nil {
		return false, err
	}
	s, err := m.Open(c.Name)
	switch {
	case errors.Is(err, ErrNotInstalled):
		s, err = m.Create(c)
		if err != nil {
			return false, fmt.Errorf("winsvc: creating %s: %w", c.Name, err)
		}
		created = true
	case err != nil:
		return false, fmt.Errorf("winsvc: opening %s: %w", c.Name, err)
	}
	defer s.Close()
	// recovery, description and environment are separate calls either way.
	if err := s.Configure(c); err != nil {
		return created, fmt.Errorf("winsvc: configuring %s: %w", c.Name, err)
	}
	return created, nil
}

// Uninstall stops the service if it runs and deletes it. A service that is
// not installed is already uninstalled.
func Uninstall(m Manager, name string, w Waits) error {
	s, err := m.Open(name)
	if errors.Is(err, ErrNotInstalled) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("winsvc: opening %s: %w", name, err)
	}
	defer s.Close()
	if err := stopAndWait(s, name, w); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("winsvc: deleting %s: %w", name, err)
	}
	return nil
}

// Start starts the service and waits for it to report Running.
func Start(m Manager, name string, w Waits) error {
	s, err := m.Open(name)
	if err != nil {
		return fmt.Errorf("winsvc: opening %s: %w", name, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, ErrAlreadyRunning) {
		return fmt.Errorf("winsvc: starting %s: %w", name, err)
	}
	return waitFor(s, name, Running, w)
}

// Stop stops the service and waits for it to report Stopped. Stopping a
// stopped service succeeds.
func Stop(m Manager, name string, w Waits) error {
	s, err := m.Open(name)
	if err != nil {
		return fmt.Errorf("winsvc: opening %s: %w", name, err)
	}
	defer s.Close()
	return stopAndWait(s, name, w)
}

// Query reports the service's state, or ErrNotInstalled.
func Query(m Manager, name string) (State, error) {
	s, err := m.Open(name)
	if err != nil {
		return 0, fmt.Errorf("winsvc: querying %s: %w", name, err)
	}
	defer s.Close()
	st, err := s.State()
	if err != nil {
		return 0, fmt.Errorf("winsvc: querying %s: %w", name, err)
	}
	return st, nil
}

func stopAndWait(s Service, name string, w Waits) error {
	st, err := s.State()
	if err != nil {
		return fmt.Errorf("winsvc: querying %s: %w", name, err)
	}
	if st == Stopped {
		return nil
	}
	if st != StopPending {
		if err := s.Stop(); err != nil && !errors.Is(err, ErrNotActive) {
			return fmt.Errorf("winsvc: stopping %s: %w", name, err)
		}
	}
	return waitFor(s, name, Stopped, w)
}

// waitFor polls until the service reaches want. Reaching Stopped while
// waiting for Running is a failure to start, reported at once rather than
// after the timeout — the service log, not this tool, has the reason.
func waitFor(s Service, name string, want State, w Waits) error {
	deadline := time.Now().Add(w.Timeout)
	for {
		st, err := s.State()
		if err != nil {
			return fmt.Errorf("winsvc: querying %s: %w", name, err)
		}
		if st == want {
			return nil
		}
		if want == Running && st == Stopped {
			return fmt.Errorf("%w: %s", ErrStartFailed, name)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"%w: %s still %s after %s, want %s",
				ErrTimeout,
				name,
				st,
				w.Timeout,
				want,
			)
		}
		time.Sleep(w.Poll)
	}
}
