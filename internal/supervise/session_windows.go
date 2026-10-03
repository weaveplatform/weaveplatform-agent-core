package supervise

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	winsec "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/environment"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
)

var (
	// errNoTokenSize: the sizing call for the token's user returned nothing.
	errNoTokenSize = errors.New("GetTokenInformation(TokenUser) returned no size")
	// errExitStatus: a non-zero exit, worded as os/exec words it.
	errExitStatus = errors.New("exit status")
)

// Seams over the calls that need a real interactive logon and LocalSystem,
// so the launch path around them runs under test as an ordinary user.
var (
	queryUserToken = func(sessionID uint32) (foundation.HANDLE, error) {
		// SE_TCB_NAME, i.e. LocalSystem. The token is the user's primary
		// token — for an administrator the UAC-filtered one, so a per-user
		// module never runs elevated.
		var h foundation.HANDLE
		if err := remotedesktop.WTSQueryUserToken(sessionID, &h); err != nil {
			return h, fmt.Errorf("WTSQueryUserToken: %w", err)
		}
		return h, nil
	}
	// interactiveDesktop is where the module's windows, clipboard and
	// hooks live. Left unset, CreateProcessAsUser puts the process on a
	// non-interactive window station: it runs, in the right session, and its
	// clipboard is a private one nobody else can see — the silent failure.
	interactiveDesktop = `winsta0\default`
)

// tokenUserSID is the string SID of the token's user, for the pipe SDDL.
func tokenUserSID(tok foundation.HANDLE) (string, error) {
	var n uint32
	_ = winsec.GetTokenInformation(
		tok,
		winsec.TokenUser,
		nil,
		&n,
	) // sizing call: fails by design and sets n
	if n == 0 {
		return "", errNoTokenSize
	}
	buf := make([]byte, n)
	if err := winsec.GetTokenInformation(tok, winsec.TokenUser, buf, &n); err != nil {
		return "", fmt.Errorf("GetTokenInformation(TokenUser): %w", err)
	}
	tu := (*winsec.TOKEN_USER)(unsafe.Pointer(&buf[0]))
	var s foundation.PWSTR
	if err := authorization.ConvertSidToStringSid(tu.User.Sid, &s); err != nil {
		return "", fmt.Errorf("ConvertSidToStringSid: %w", err)
	}
	defer func() { _, _ = foundation.LocalFree(foundation.HLOCAL(unsafe.Pointer(s))) }()
	return utf16Z(unsafe.Pointer(s)), nil
}

// environmentFor is the user's own environment — USERPROFILE, APPDATA,
// TEMP — as a logon would build it, not core's SYSTEM one.
func environmentFor(tok foundation.HANDLE) ([]string, error) {
	var block unsafe.Pointer
	if err := environment.CreateEnvironmentBlock(&block, tok, false); err != nil {
		return nil, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer func() { _ = environment.DestroyEnvironmentBlock(block) }()
	// its length is only known by walking it.
	n := 0
	for p := block; ; p = unsafe.Add(p, 2) {
		n++
		if *(*uint16)(p) == 0 && *(*uint16)(unsafe.Add(p, 2)) == 0 {
			n++
			break
		}
	}
	return decodeEnvBlock(unsafe.Slice((*uint16)(block), n)), nil
}

// utf16Z reads a NUL-terminated UTF-16 string.
func utf16Z(p unsafe.Pointer) string {
	var s []uint16
	for ; *(*uint16)(p) != 0; p = unsafe.Add(p, 2) {
		s = append(s, *(*uint16)(p))
	}
	return string(utf16.Decode(s))
}

// startAsUser is CreateProcessAsUser onto the interactive desktop, which
// os/exec cannot do: syscall.SysProcAttr takes a token but has no field for
// STARTUPINFO.lpDesktop. Everything else mirrors os/exec — stdio over
// pipes, only those three handles inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
// and the wait drains output before reporting the exit.
func startAsUser(
	tok foundation.HANDLE,
	bin string,
	env []string,
	stdout, stderr io.Writer,
) (*child, error) {
	nul, err := os.Open(os.DevNull)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", os.DevNull, err)
	}
	defer nul.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	closeAll := func() {
		outR.Close()
		errR.Close()
	}
	pi, err := createAsUser(tok, bin, env, nul, outW, errW)
	// The child holds its own copies now; the parent's write ends must go, or
	// the readers never see EOF.
	outW.Close()
	errW.Close()
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("exec: CreateProcessAsUser: %w", err)
	}
	_ = foundation.CloseHandle(pi.HThread)

	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); _, _ = io.Copy(stdout, outR) }()
	go func() { defer copies.Done(); _, _ = io.Copy(stderr, errR) }()
	// terminate whatever process holds that value next.
	var mu sync.Mutex
	h := pi.HProcess
	return &child{
		pid: int(pi.DwProcessId),
		kill: func() error {
			mu.Lock()
			defer mu.Unlock()
			if h == 0 {
				return nil
			}
			return threading.TerminateProcess(h, 1)
		},
		wait: func() (int, error) {
			_, _ = threading.WaitForSingleObject(h, threading.INFINITE)
			var code uint32
			cerr := threading.GetExitCodeProcess(h, &code)
			copies.Wait()
			closeAll()
			mu.Lock()
			_ = foundation.CloseHandle(h)
			h = 0
			mu.Unlock()
			if cerr != nil {
				return -1, fmt.Errorf("GetExitCodeProcess: %w", cerr)
			}
			if code != 0 {
				return int(code), fmt.Errorf("%w %d", errExitStatus, code)
			}
			return 0, nil
		},
	}, nil
}

func createAsUser(
	tok foundation.HANDLE,
	bin string,
	env []string,
	stdin, stdout, stderr *os.File,
) (*threading.PROCESS_INFORMATION, error) {
	handles := []foundation.HANDLE{
		foundation.HANDLE(
			stdin.Fd(),
		),
		foundation.HANDLE(stdout.Fd()),
		foundation.HANDLE(stderr.Fd()),
	}
	// Inheritable only for the length of the call, under the lock os/exec
	// takes for the same reason.
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()
	for _, h := range handles {
		if err := foundation.SetHandleInformation(
			h,
			uint32(foundation.HANDLE_FLAG_INHERIT),
			foundation.HANDLE_FLAG_INHERIT,
		); err != nil {
			return nil, fmt.Errorf("SetHandleInformation: %w", err)
		}
	}

	var size uintptr
	_ = threading.InitializeProcThreadAttributeList(
		0,
		1,
		&size,
	) // sizing call: fails by design and sets size
	// []uintptr, not []byte: the list must be pointer-aligned.
	mem := make([]uintptr, (size+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	al := threading.LPPROC_THREAD_ATTRIBUTE_LIST(uintptr(unsafe.Pointer(&mem[0])))
	if err := threading.InitializeProcThreadAttributeList(al, 1, &size); err != nil {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", err)
	}
	defer threading.DeleteProcThreadAttributeList(al)
	if err := threading.UpdateProcThreadAttribute(
		al,
		0,
		uintptr(threading.PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
		unsafe.Pointer(
			&handles[0],
		),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
		nil,
		nil,
	); err != nil {
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %w", err)
	}

	var desktop *uint16
	if interactiveDesktop != "" {
		d := utf16.Encode([]rune(interactiveDesktop + "\x00"))
		desktop = &d[0]
	}
	si := threading.STARTUPINFOEXW{
		StartupInfo: threading.STARTUPINFOW{
			LpDesktop:  desktop,
			DwFlags:    threading.STARTF_USESTDHANDLES,
			HStdInput:  handles[0],
			HStdOutput: handles[1],
			HStdError:  handles[2],
		},
		LpAttributeList: al,
	}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	cmdline := utf16.Encode([]rune(syscall.EscapeArg(bin) + "\x00"))
	block := encodeEnvBlock(env)
	var pi threading.PROCESS_INFORMATION
	// CREATE_NO_WINDOW: a console-subsystem module would otherwise open a
	// console window on the user's desktop.
	err := threading.CreateProcessAsUser(
		tok,
		&bin,
		&cmdline[0],
		nil,
		nil,
		true,
		threading.CREATE_UNICODE_ENVIRONMENT|threading.EXTENDED_STARTUPINFO_PRESENT|threading.CREATE_NO_WINDOW,
		unsafe.Pointer(&block[0]),
		nil,
		&si.StartupInfo,
		&pi,
	)
	runtime.KeepAlive(mem)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(desktop)
	// Not left inheritable: a later CreateProcess with bInheritHandles and
	// no handle list would leak them into an unrelated child.
	for _, h := range handles {
		_ = foundation.SetHandleInformation(h, uint32(foundation.HANDLE_FLAG_INHERIT), 0)
	}
	if err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	return &pi, nil
}
