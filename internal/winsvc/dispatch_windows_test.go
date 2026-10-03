package winsvc

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	svc "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

// A test process is not a service: the real dispatcher says so at once,
// and Run turns that into ErrNotService so weaveboot runs interactively.
func TestRunOutsideSCMIsNotService(t *testing.T) {
	err := Run(func(context.Context) error {
		t.Error("body ran without an SCM")
		return nil
	})
	if !errors.Is(err, ErrNotService) {
		t.Fatalf("Run = %v, want ErrNotService", err)
	}
}

func TestIsServiceFalseUnderGoTest(t *testing.T) {
	svc, err := IsService()
	if err != nil || svc {
		t.Fatalf("IsService = %v, %v", svc, err)
	}
	procs, err := processSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range procs {
		if p.PID == uint32(os.Getpid()) {
			found = p.Parent != 0 && p.Exe != ""
		}
	}
	if !found {
		t.Fatal("snapshot does not contain this process with its parent")
	}
}

type fakeSCM struct {
	mu       sync.Mutex
	name     string
	statuses []svc.SERVICE_STATUS
	running  chan struct{}
}

// stubDispatch replaces the SCM side: the dispatcher calls serviceMain on
// the caller's goroutine, the way the real one calls it on a thread of its
// own, with argv[0] set to the service name.
func stubDispatch(t *testing.T, f *fakeSCM, regErr error) {
	t.Helper()
	origStart, origReg, origSet, origTick := startDispatcher, registerHandler, setStatus, checkpointTick
	t.Cleanup(func() {
		startDispatcher, registerHandler, setStatus, checkpointTick = origStart, origReg, origSet, origTick
	})
	checkpointTick = 5 * time.Millisecond
	startDispatcher = func(table *svc.SERVICE_TABLE_ENTRYW) error {
		if table.LpServiceName == nil || table.LpServiceProc == 0 {
			t.Error("dispatch table entry is incomplete")
		}
		name, _ := syscall.UTF16PtrFromString("WeaveAgentTest")
		argv := []*uint16{name}
		serviceMain(1, &argv[0])
		return nil
	}
	registerHandler = func(name string, proc svc.LPHANDLER_FUNCTION_EX, _ unsafe.Pointer) (svc.SERVICE_STATUS_HANDLE, error) {
		f.mu.Lock()
		f.name = name
		f.mu.Unlock()
		if proc == 0 {
			t.Error("no control handler registered")
		}
		return 1, regErr
	}
	setStatus = func(_ svc.SERVICE_STATUS_HANDLE, st *svc.SERVICE_STATUS) error {
		f.mu.Lock()
		f.statuses = append(f.statuses, *st)
		f.mu.Unlock()
		if st.DwCurrentState == svc.SERVICE_RUNNING {
			select {
			case f.running <- struct{}{}:
			default:
			}
		}
		return nil
	}
}

func TestServiceMainLifecycle(t *testing.T) {
	f := &fakeSCM{running: make(chan struct{}, 1)}
	stubDispatch(t, f, nil)
	go func() {
		<-f.running
		if rc := ctrlHandler(uintptr(ControlStop), 0, 0, 0); rc != 0 {
			t.Errorf("stop returned %d", rc)
		}
	}()
	stopped := false
	err := Run(func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // a drain long enough to checkpoint
		stopped = true
		return nil
	})
	if err != nil || !stopped {
		t.Fatalf("Run = %v, stopped=%v", err, stopped)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name != "WeaveAgentTest" {
		t.Fatalf("handler registered for %q, want the name from argv[0]", f.name)
	}
	first, last := f.statuses[0], f.statuses[len(f.statuses)-1]
	if first.DwCurrentState != svc.SERVICE_START_PENDING ||
		first.DwServiceType != svc.SERVICE_WIN32_OWN_PROCESS {
		t.Fatalf("first status %+v", first)
	}
	if last.DwCurrentState != svc.SERVICE_STOPPED || last.DwWin32ExitCode != 0 {
		t.Fatalf("last status %+v", last)
	}
	sawPending := false
	for _, s := range f.statuses {
		if s.DwCurrentState == svc.SERVICE_RUNNING &&
			s.DwControlsAccepted != svc.SERVICE_ACCEPT_STOP|svc.SERVICE_ACCEPT_PRESHUTDOWN {
			t.Fatalf("running accepts %#x", s.DwControlsAccepted)
		}
		if s.DwCurrentState == svc.SERVICE_STOP_PENDING {
			sawPending = true
			if s.DwWaitHint == 0 {
				t.Fatal("stop-pending without a wait hint")
			}
		}
	}
	if !sawPending {
		t.Fatal("never reported stop-pending")
	}
}

func TestServiceMainRegisterFailure(t *testing.T) {
	f := &fakeSCM{running: make(chan struct{}, 1)}
	stubDispatch(t, f, errors.New("denied"))
	err := Run(func(context.Context) error {
		t.Error("body ran without a control handler")
		return nil
	})
	if err == nil {
		t.Fatal("Run succeeded without a control handler")
	}
}

func TestRunDispatcherError(t *testing.T) {
	orig := startDispatcher
	t.Cleanup(func() { startDispatcher = orig })
	startDispatcher = func(*svc.SERVICE_TABLE_ENTRYW) error { return syscall.Errno(foundation.ERROR_INVALID_DATA) }
	if err := Run(
		func(context.Context) error { return nil },
	); err == nil ||
		errors.Is(err, ErrNotService) {
		t.Fatalf("Run = %v", err)
	}
}

func TestCtrlHandlerQueueing(t *testing.T) {
	origTimeout := ctrlQueueTimeout
	ctrlQueueTimeout = 10 * time.Millisecond
	t.Cleanup(func() { ctrlQueueTimeout = origTimeout })
	drain := func() {
		for len(svcCtrl) > 0 {
			<-svcCtrl
		}
	}
	drain()
	t.Cleanup(drain)

	if rc := ctrlHandler(0xFFFF, 0, 0, 0); rc != uintptr(foundation.ERROR_CALL_NOT_IMPLEMENTED) {
		t.Fatalf("unknown control returned %d", rc)
	}
	// Fill the queue: neither an Interrogate nor a stop may hang the
	// dispatcher thread when Serve is not draining it.
	for i := 0; i < cap(svcCtrl); i++ {
		svcCtrl <- ControlInterrogate
	}
	start := time.Now()
	if rc := ctrlHandler(uintptr(ControlInterrogate), 0, 0, 0); rc != 0 {
		t.Fatalf("interrogate returned %d", rc)
	}
	if rc := ctrlHandler(uintptr(ControlPreShutdown), 0, 0, 0); rc != 0 {
		t.Fatalf("preshutdown returned %d", rc)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("handler blocked on a full queue")
	}
	// With room, a stop is queued.
	drain()
	ctrlHandler(uintptr(ControlShutdown), 0, 0, 0)
	if c := <-svcCtrl; c != ControlShutdown {
		t.Fatalf("queued %d", c)
	}
}

func TestNativeStatus(t *testing.T) {
	n := nativeStatus(
		Status{
			State:           StopPending,
			CheckPoint:      3,
			WaitHint:        1500 * time.Millisecond,
			Win32ExitCode:   1066,
			ServiceExitCode: 1,
		},
	)
	if n.DwCurrentState != svc.SERVICE_STOP_PENDING || n.DwCheckPoint != 3 ||
		n.DwWaitHint != 1500 ||
		n.DwWin32ExitCode != 1066 ||
		n.DwServiceSpecificExitCode != 1 {
		t.Fatalf("%+v", n)
	}
}
