package winsvc

import (
	"errors"
	"sync"
)

// fakeManager is an in-memory SCM. Each service's state advances one step
// per State() call while pending, so the wait loops are exercised.
type fakeManager struct {
	mu        sync.Mutex
	services  map[string]*fakeService
	openErr   error
	createErr error
	log       []string
}

func newFake() *fakeManager { return &fakeManager{services: map[string]*fakeService{}} }

func (m *fakeManager) record(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, s)
}

func (m *fakeManager) Open(name string) (Service, error) {
	if m.openErr != nil {
		return nil, m.openErr
	}
	s, ok := m.services[name]
	if !ok || s.deleted {
		return nil, ErrNotInstalled
	}
	return s, nil
}

func (m *fakeManager) Create(c Config) (Service, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.record("create " + c.Name)
	s := &fakeService{m: m, state: Stopped}
	m.services[c.Name] = s
	return s, nil
}

func (m *fakeManager) Close() error { return nil }

type fakeService struct {
	m       *fakeManager
	cfg     Config
	configs int
	state   State
	deleted bool

	// Behaviour knobs.
	configureErr, stateErr, startErr, stopErr, deleteErr error
	startFails                                           bool // goes Stopped instead of Running
	stuck                                                bool // pending states never advance
	stateErrAfter                                        int  // State() succeeds this many times, then stateErr
	stateCalls                                           int
}

func (s *fakeService) Configure(c Config) error {
	if s.configureErr != nil {
		return s.configureErr
	}
	s.cfg = c
	s.configs++
	s.m.record("configure " + c.Name)
	return nil
}

func (s *fakeService) State() (State, error) {
	s.stateCalls++
	if s.stateErr != nil && s.stateCalls > s.stateErrAfter {
		return 0, s.stateErr
	}
	st := s.state
	if !s.stuck {
		switch s.state {
		case StartPending:
			s.state = Running
			if s.startFails {
				s.state = Stopped
			}
		case StopPending:
			s.state = Stopped
		}
	}
	return st, nil
}

func (s *fakeService) Start() error {
	if s.startErr != nil {
		return s.startErr
	}
	s.m.record("start")
	if s.state == Running {
		return ErrAlreadyRunning
	}
	s.state = StartPending
	return nil
}

func (s *fakeService) Stop() error {
	if s.stopErr != nil {
		return s.stopErr
	}
	s.m.record("stop")
	if s.state == Stopped {
		return ErrNotActive
	}
	s.state = StopPending
	return nil
}

func (s *fakeService) Delete() error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.m.record("delete")
	s.deleted = true
	return nil
}

func (s *fakeService) Close() error { return nil }

var errBoom = errors.New("boom")
