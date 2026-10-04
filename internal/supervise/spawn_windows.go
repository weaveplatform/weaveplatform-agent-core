package supervise

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	winsec "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	"golang.org/x/sys/windows"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// errNoExecDir: a launch with no layout to stage the binary under.
var errNoExecDir = errors.New("no exec dir to stage the module binary in")

// errBadPID: a process id that does not fit a Windows DWORD.
var errBadPID = errors.New("process id out of range")

// jobHandle wraps a Job Object with kill-on-close: when core dies, the
// handle closes and every module process dies with it. Contain (spec §8).
type jobHandle struct {
	h windows.Handle
}

// target is where and as whom one launch runs. A system module runs from
// core's own token (restricted for "service"); a per-user module runs from
// the console user's token, which only SYSTEM can obtain.
type target struct {
	layout layout.Layout
	m      *manifest.Manifest
	sess   *session.Session
	token  foundation.HANDLE
	sid    string
}

func newTarget(l layout.Layout, m *manifest.Manifest, sess *session.Session) (*target, error) {
	t := &target{layout: l, m: m, sess: sess}
	if sess == nil {
		return t, nil
	}
	id, err := strconv.ParseUint(sess.ID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("console session id %q: %w", sess.ID, err)
	}
	tok, err := queryUserToken(uint32(id))
	if err != nil {
		return nil, fmt.Errorf(
			"user token for session %d (core must run as LocalSystem): %w",
			id,
			err,
		)
	}
	sid, err := tokenUserSID(tok)
	if err != nil {
		_ = foundation.CloseHandle(tok)
		return nil, fmt.Errorf("user of session %d: %w", id, err)
	}
	t.token, t.sid = tok, sid
	return t, nil
}

func (t *target) close() {
	if t.token != 0 {
		_ = foundation.CloseHandle(t.token)
		t.token = 0
	}
}

// stageBinary copies the module binary under the layout's ExecDir and
// returns the copy, which is what is verified and exec'd. Windows keeps a
// running image's file open without FILE_SHARE_DELETE, so a module run from
// where it is installed could not be removed or replaced while it runs: an
// installer, the lifecycle manager's prune and core's module reload would all
// fail with "Access is denied". The copy takes that lock instead.
//
// Verification runs on the copy, not the original: the Authenticode
// signature is embedded, so the copy carries it, and checking the file that
// is actually exec'd leaves no window between the check and the launch. The
// copy lives in core's state tree, whose DACL (SYSTEM and Administrators,
// inherited; see winsvc.RestrictDir) nobody else can write. Process creation
// opens the image with core's token, so a restricted or per-user module needs
// no access of its own to it.
//
// Each launch gets a fresh directory: the previous copy may still be held
// for a moment after its process exits, and must not stop the next launch.
// Stale ones are removed here when they can be, when the module stops, and
// by SweepOrphans.
func (t *target) stageBinary(bin string) (string, error) {
	if t.layout.ExecDir == "" {
		return "", errNoExecDir
	}
	root := t.layout.ModuleExecDir(t.m.ID)
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("creating staging dir: %w", err)
	}
	dir, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return "", fmt.Errorf("creating staging dir: %w", err)
	}
	staged := filepath.Join(dir, filepath.Base(bin))
	if err := copyExecutable(bin, staged); err != nil {
		return "", err
	}
	return staged, nil
}

// prepareSocketDir is a no-op on Windows: the host endpoint is a named pipe
// whose access is its SDDL, not a directory's ownership.
func (t *target) prepareSocketDir(_, _ string) error { return nil }

// listenHost serves the module's host pipe. A per-user module's pipe admits
// that user's SID beside SYSTEM and Administrators — otherwise the module,
// running as the user, cannot dial core at all. Peer identity on a pipe is
// not checked beyond the SDDL (see internal/protocol/ipc peercred_windows.go); the
// handshake token is what separates this module from the user's other
// processes.
func (t *target) listenHost(ctx context.Context, addr string) (net.Listener, error) {
	var (
		l   net.Listener
		err error
	)
	if t.sess == nil {
		l, err = ipc.Listen(ctx, addr)
	} else {
		l, err = ipc.ListenPipeSDDL(addr, sessionPipeSDDL(t.sid))
	}
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", addr, err)
	}
	return l, nil
}

// sessionPipeSDDL is the default host-pipe SDDL (SYSTEM + Administrators,
// generic all) plus read/write for one user SID.
func sessionPipeSDDL(sid string) string {
	return "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + sid + ")"
}

func (t *target) start(bin string, extra []string, stdout, stderr io.Writer) (*child, error) {
	if t.sess == nil {
		// bin is the verified module binary (Verifier.Verify ran on it), and
		// the supervisor owns the module's lifetime and stops it itself; a
		// context-bound Cmd would kill the module when a context ended.
		//nolint:noctx,gosec // verified binary; lifetime owned by the supervisor
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), extra...)
		cleanup, err := applyPrivilege(cmd, t.m)
		if err != nil {
			return nil, fmt.Errorf("privilege setup: %w", err)
		}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		err = cmd.Start()
		cleanup() // release any privilege token now the child owns its copy
		if err != nil {
			return nil, fmt.Errorf("exec: %w", err)
		}
		return commandChild(cmd), nil
	}
	userEnv, err := environmentFor(t.token)
	if err != nil {
		return nil, fmt.Errorf("user environment: %w", err)
	}
	return startAsUser(
		t.token,
		bin,
		mergeEnv(userEnv, nil, weaveEnv(os.Environ()), extra),
		stdout,
		stderr,
	)
}

// applyPrivilege drops credentials per the manifest. On Windows the
// "service" drop is a restricted primary token — same user, maximum
// privileges removed (DISABLE_MAX_PRIVILEGE) — assigned to the child via
// SysProcAttr.Token. It returns a cleanup that MUST be called after
// cmd.Start: os/exec does not take ownership of a caller-supplied token
// handle, so without this it leaks one handle per launch — and launches
// are a hot loop in a privileged service.
func applyPrivilege(cmd *exec.Cmd, m *manifest.Manifest) (cleanup func(), err error) {
	cleanup = func() {}
	switch m.Privilege {
	case manifest.PrivilegeSystem:
		return cleanup, nil
	case manifest.PrivilegeService:
		var procToken foundation.HANDLE
		if err := threading.OpenProcessToken(
			threading.GetCurrentProcess(),
			winsec.TOKEN_ACCESS_MASK(
				windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
			),
			&procToken,
		); err != nil {
			return cleanup, fmt.Errorf("opening process token: %w", err)
		}
		defer func() { _ = windows.CloseHandle(windows.Handle(procToken)) }()
		var restricted foundation.HANDLE
		if err := winsec.CreateRestrictedToken(procToken, winsec.DISABLE_MAX_PRIVILEGE,
			nil, nil, nil, &restricted); err != nil {
			return cleanup, fmt.Errorf("creating restricted token: %w", err)
		}
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Token = syscall.Token(restricted)
		return func() { _ = windows.CloseHandle(windows.Handle(restricted)) }, nil
	default:
		// placementError refuses this at Add; reaching here is a bug, and
		// the safe answer to a bug in privilege code is not to launch.
		return cleanup, fmt.Errorf("privilege %q %w", m.Privilege, errNoSystemIdentity)
	}
}

func postSpawn(pid int) (jobHandle, error) {
	if pid < 0 || pid > math.MaxUint32 {
		return jobHandle{}, fmt.Errorf("%w: %d", errBadPID, pid)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return jobHandle{}, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return jobHandle{}, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	proc, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return jobHandle{}, fmt.Errorf("OpenProcess: %w", err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		_ = windows.CloseHandle(job)
		return jobHandle{}, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return jobHandle{h: job}, nil
}

func killProc(c *child, job jobHandle) {
	if job.h != 0 {
		// Terminating the job kills the whole tree.
		_ = windows.TerminateJobObject(job.h, 1)
		return
	}
	_ = c.kill()
}

func closeJob(job jobHandle) {
	if job.h != 0 {
		_ = windows.CloseHandle(job.h)
	}
}
