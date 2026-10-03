package winsvc

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/diagnostics/toolhelp"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
	svc "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

// IsService reports whether the SCM started this process: session 0 and a
// services.exe parent (see startedBySCM). Run's ErrNotService is the
// backstop if this is ever wrong in the "yes" direction.
func IsService() (bool, error) {
	pid := uint32(os.Getpid()) //nolint:gosec // G115: a Windows process id is a DWORD
	var session uint32
	if err := remotedesktop.ProcessIdToSessionId(pid, &session); err != nil {
		return false, fmt.Errorf("winsvc: session of this process: %w", err)
	}
	if session != 0 {
		return false, nil
	}
	procs, err := processSnapshot()
	if err != nil {
		return false, err
	}
	return startedBySCM(procs, pid), nil
}

func processSnapshot() ([]procEntry, error) {
	snap, err := toolhelp.CreateToolhelp32Snapshot(toolhelp.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("winsvc: process snapshot: %w", err)
	}
	defer func() { _ = foundation.CloseHandle(snap) }()
	var out []procEntry
	e := toolhelp.PROCESSENTRY32W{DwSize: uint32(unsafe.Sizeof(toolhelp.PROCESSENTRY32W{}))}
	for err := toolhelp.Process32FirstW(snap, &e); err == nil; err = toolhelp.Process32NextW(snap, &e) {
		out = append(out, procEntry{
			PID: e.Th32ProcessID, Parent: e.Th32ParentProcessID,
			Exe: syscall.UTF16ToString(e.SzExeFile[:]),
		})
	}
	return out, nil
}

// The dispatcher's callbacks are plain C function pointers with no closure
// context, so the body and control channel they need live here. One service
// per process makes that safe.
var (
	callbacksOnce      sync.Once
	mainProc, ctrlProc uintptr

	svcBody   func(context.Context) error
	svcCtrl   = make(chan Control, 16)
	svcResult error

	// Seams: tests drive serviceMain and ctrlHandler directly, without an SCM.
	startDispatcher = svc.StartServiceCtrlDispatcher
	registerHandler = svc.RegisterServiceCtrlHandlerEx
	setStatus       = svc.SetServiceStatus
	checkpointTick  = time.Second
	// How long ctrlHandler waits to queue a stop before giving up on it.
	ctrlQueueTimeout = 5 * time.Second
)

// Run hands the process to the SCM and runs body as the service until a
// stop control cancels it (Serve). It returns ErrNotService when the SCM did
// not start this process, so the caller can run interactively instead.
func Run(body func(context.Context) error) error {
	callbacksOnce.Do(func() {
		mainProc = syscall.NewCallback(serviceMain)
		ctrlProc = syscall.NewCallback(ctrlHandler)
	})
	svcBody = body
	// The name is ignored for a SERVICE_WIN32_OWN_PROCESS service but must
	// not be NULL; the table ends with a zeroed entry.
	var empty uint16
	table := [2]svc.SERVICE_TABLE_ENTRYW{
		{LpServiceName: &empty, LpServiceProc: svc.LPSERVICE_MAIN_FUNCTIONW(mainProc)},
	}
	if err := startDispatcher(&table[0]); err != nil {
		if errors.Is(err, syscall.Errno(foundation.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)) {
			return ErrNotService
		}
		return fmt.Errorf("winsvc: service dispatcher: %w", err)
	}
	return svcResult
}

// serviceMain runs on a thread the SCM creates. It returns only after
// Serve has reported Stopped, which is what lets the dispatcher return.
func serviceMain(argc uintptr, argv **uint16) uintptr {
	name := ""
	if argc > 0 && argv != nil {
		// argv[0] is the service's registered name.
		name = win32.UTF16ToString(*argv)
	}
	h, err := registerHandler(name, svc.LPHANDLER_FUNCTION_EX(ctrlProc), nil)
	if err != nil {
		svcResult = fmt.Errorf("winsvc: registering control handler: %w", err)
		return 0
	}
	report := func(s Status) {
		st := nativeStatus(s)
		// Nothing useful can be done with a failure: the SCM is the only
		// party that could be told.
		_ = setStatus(h, &st)
	}
	svcResult = Serve(svcCtrl, report, svcBody, checkpointTick)
	return 0
}

// ctrlHandler runs on the dispatcher thread and must return promptly; it
// only queues the control for Serve. An Interrogate is dropped when the
// queue is full — the next one answers it — but a stop is never dropped:
// nothing re-sends it, and a lost stop is a service that ignores shutdown.
// The bound keeps a wedged Serve from wedging the dispatcher with it.
func ctrlHandler(ctl, _, _, _ uintptr) uintptr {
	switch c := Control(ctl); c { //nolint:gosec // G115: the SCM passes a DWORD control code in a uintptr
	case ControlInterrogate:
		select {
		case svcCtrl <- c:
		default:
		}
		return 0
	case ControlStop, ControlShutdown, ControlPreShutdown:
		select {
		case svcCtrl <- c:
		case <-time.After(ctrlQueueTimeout):
		}
		return 0
	}
	return uintptr(foundation.ERROR_CALL_NOT_IMPLEMENTED)
}

func nativeStatus(s Status) svc.SERVICE_STATUS {
	return svc.SERVICE_STATUS{
		DwServiceType:             svc.SERVICE_WIN32_OWN_PROCESS,
		DwCurrentState:            svc.SERVICE_STATUS_CURRENT_STATE(s.State),
		DwControlsAccepted:        s.Accepts,
		DwWin32ExitCode:           s.Win32ExitCode,
		DwServiceSpecificExitCode: s.ServiceExitCode,
		DwCheckPoint:              s.CheckPoint,
		DwWaitHint:                uint32(min(max(s.WaitHint/time.Millisecond, 0), math.MaxUint32)),
	}
}
