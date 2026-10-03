package winsvc

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	reg "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	svc "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

// localSystem with an empty (not nil) password is how ChangeServiceConfig
// is told to move an existing service back to LocalSystem; nil would leave
// whatever account an operator had set.
const localSystem = "LocalSystem"

type scmManager struct{ h svc.SC_HANDLE }

// NewManager connects to the local SCM with the rights install needs, so a
// non-elevated caller fails here, before anything has been changed.
func NewManager() (Manager, error) {
	h, err := svc.OpenSCManager(nil, nil, svc.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return nil, fmt.Errorf(
			"winsvc: connecting to the service control manager (is this elevated?): %w",
			err,
		)
	}
	return &scmManager{h: h}, nil
}

func (m *scmManager) Close() error {
	if err := svc.CloseServiceHandle(m.h); err != nil {
		return fmt.Errorf("winsvc: closing the service control manager: %w", err)
	}
	return nil
}

func (m *scmManager) Open(name string) (Service, error) {
	h, err := svc.OpenService(m.h, name, svc.SERVICE_ALL_ACCESS)
	if err != nil {
		return nil, mapErr(err)
	}
	return &scmService{h: h, name: name}, nil
}

func (m *scmManager) Create(c Config) (Service, error) {
	cmd, acct := c.CommandLine(), localSystem
	h, err := svc.CreateService(m.h, c.Name, &c.DisplayName, svc.SERVICE_ALL_ACCESS,
		svc.SERVICE_WIN32_OWN_PROCESS, svc.SERVICE_AUTO_START, svc.SERVICE_ERROR_NORMAL,
		&cmd, nil, nil, nil, &acct, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	return &scmService{h: h, name: c.Name}, nil
}

type scmService struct {
	h    svc.SC_HANDLE
	name string
}

func (s *scmService) Close() error {
	if err := svc.CloseServiceHandle(s.h); err != nil {
		return fmt.Errorf("winsvc: closing %s: %w", s.name, err)
	}
	return nil
}

// Configure sets every field Install owns, including the ones that are
// already at their defaults on a fresh service (delayed start off), so a
// re-install reverts a hand edit rather than preserving it.
//
// Plain automatic start, not delayed: delayed auto-start holds the service
// back roughly two minutes after boot, and the agent is the channel a
// host uses to drive a freshly booted guest — the same reasoning that keeps
// the systemd unit off network-online.target.
func (s *scmService) Configure(c Config) error {
	cmd, acct, pw := c.CommandLine(), localSystem, ""
	if err := svc.ChangeServiceConfig(s.h, svc.SERVICE_WIN32_OWN_PROCESS, svc.SERVICE_AUTO_START,
		svc.SERVICE_ERROR_NORMAL, &cmd, nil, nil, nil, &acct, &pw, &c.DisplayName); err != nil {
		return fmt.Errorf("base configuration: %w", err)
	}

	desc, err := syscall.UTF16PtrFromString(c.Description)
	if err != nil {
		return fmt.Errorf("description: %w", err)
	}
	d := svc.SERVICE_DESCRIPTIONW{LpDescription: desc}
	if err := svc.ChangeServiceConfig2(
		s.h,
		svc.SERVICE_CONFIG_DESCRIPTION,
		unsafe.Pointer(&d),
	); err != nil {
		return fmt.Errorf("description: %w", err)
	}

	// Three identical actions so services.msc shows "Restart the Service"
	// for first, second and subsequent failures; the SCM repeats the last
	// action anyway.
	delay := uint32(RestartDelay / time.Millisecond)
	actions := [3]svc.SC_ACTION{
		{Type: svc.SC_ACTION_RESTART, Delay: delay},
		{Type: svc.SC_ACTION_RESTART, Delay: delay},
		{Type: svc.SC_ACTION_RESTART, Delay: delay},
	}
	fa := svc.SERVICE_FAILURE_ACTIONSW{
		DwResetPeriod: uint32(FailureResetPeriod / time.Second),
		CActions:      uint32(len(actions)),
		LpsaActions:   &actions[0],
	}
	if err := svc.ChangeServiceConfig2(
		s.h,
		svc.SERVICE_CONFIG_FAILURE_ACTIONS,
		unsafe.Pointer(&fa),
	); err != nil {
		return fmt.Errorf("recovery actions: %w", err)
	}
	runtime.KeepAlive(actions)

	// Without this flag the SCM applies recovery only to a crash. weaveboot
	// that gives up reports STOPPED with a service-specific error (Serve),
	// which is a non-crash failure — and Restart=always restarts that too.
	flag := svc.SERVICE_FAILURE_ACTIONS_FLAG{FFailureActionsOnNonCrashFailures: 1}
	if err := svc.ChangeServiceConfig2(
		s.h,
		svc.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
		unsafe.Pointer(&flag),
	); err != nil {
		return fmt.Errorf("recovery on non-crash failures: %w", err)
	}

	ps := svc.SERVICE_PRESHUTDOWN_INFO{
		DwPreshutdownTimeout: uint32(PreshutdownTimeout / time.Millisecond),
	}
	if err := svc.ChangeServiceConfig2(
		s.h,
		svc.SERVICE_CONFIG_PRESHUTDOWN_INFO,
		unsafe.Pointer(&ps),
	); err != nil {
		return fmt.Errorf("preshutdown timeout: %w", err)
	}

	delayed := svc.SERVICE_DELAYED_AUTO_START_INFO{FDelayedAutostart: 0}
	if err := svc.ChangeServiceConfig2(
		s.h,
		svc.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
		unsafe.Pointer(&delayed),
	); err != nil {
		return fmt.Errorf("delayed start: %w", err)
	}

	if err := setEnvironment(s.name, c.Env); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	return nil
}

func (s *scmService) State() (State, error) {
	var st svc.SERVICE_STATUS
	if err := svc.QueryServiceStatus(s.h, &st); err != nil {
		return 0, fmt.Errorf("winsvc: querying %s: %w", s.name, err)
	}
	return State(st.DwCurrentState), nil
}

func (s *scmService) Start() error { return mapErr(svc.StartService(s.h, nil)) }

func (s *scmService) Stop() error {
	var st svc.SERVICE_STATUS
	return mapErr(svc.ControlService(s.h, svc.SERVICE_CONTROL_STOP, &st))
}

func (s *scmService) Delete() error {
	err := svc.DeleteService(s.h)
	if err == nil || errors.Is(err, syscall.Errno(foundation.ERROR_SERVICE_MARKED_FOR_DELETE)) {
		return nil
	}
	return fmt.Errorf("winsvc: deleting %s: %w", s.name, err)
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.Errno(foundation.ERROR_SERVICE_DOES_NOT_EXIST)):
		return ErrNotInstalled
	case errors.Is(err, syscall.Errno(foundation.ERROR_SERVICE_NOT_ACTIVE)):
		return ErrNotActive
	case errors.Is(err, syscall.Errno(foundation.ERROR_SERVICE_ALREADY_RUNNING)):
		return ErrAlreadyRunning
	}
	return err
}

func serviceKey(name string) string {
	return `SYSTEM\CurrentControlSet\Services\` + name
}

// setEnvironment writes the service's Environment value. The SCM has no API
// for it — sc.exe and the services snap-in cannot set it either — so the
// registry under the service key is the interface, and the SCM reads it at
// each start.
func setEnvironment(name string, env []string) error {
	var k reg.HKEY
	sub := serviceKey(name)
	if rc := reg.RegOpenKeyEx(
		reg.HKEY_LOCAL_MACHINE,
		&sub,
		0,
		reg.KEY_SET_VALUE|reg.KEY_WOW64_64KEY,
		&k,
	); rc != 0 {
		return syscall.Errno(rc)
	}
	defer reg.RegCloseKey(k)
	value := "Environment"
	if len(env) == 0 {
		// Removing every --env must remove the variables, not keep the old
		// ones because there was nothing to write.
		if rc := reg.RegDeleteValue(k, &value); rc != 0 && rc != foundation.ERROR_FILE_NOT_FOUND {
			return syscall.Errno(rc)
		}
		return nil
	}
	if rc := reg.RegSetValueEx(k, &value, reg.REG_MULTI_SZ, EncodeMultiSZ(env)); rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}
