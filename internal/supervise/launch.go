package supervise

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// errProtocolUnsupported: the module exited 78 — clean refusal, never
// restarted.
var errProtocolUnsupported = errors.New("module refused protocol window")

var (
	// errHandshakeTimeout: the module printed no handshake line in time.
	errHandshakeTimeout = errors.New("timeout waiting for handshake line")
	// errOutsideWindow: the module's handshake named a protocol core does
	// not speak.
	errOutsideWindow = errors.New("outside window")
	// errRequirementsUnmet: the module declared, at Init, a capability core
	// does not have.
	errRequirementsUnmet = errors.New("runtime requirements unmet")
)

// proc is one live module process with its harness.
type proc struct {
	child    *child
	conn     *grpc.ClientConn
	client   agentv1.ModuleServiceClient
	hostSrv  *grpc.Server
	line     handshake.Line
	initResp *agentv1.InitResponse
	job      jobHandle
	exited   chan error // buffered(1); receives the child's wait result exactly once
}

// child is a spawned module process, however it was started: os/exec for
// most, CreateProcessAsUser for a Windows user session, which os/exec cannot
// do because it cannot name the interactive desktop.
type child struct {
	pid  int
	kill func() error
	// wait blocks until the process exits and its output is drained. Call
	// exactly once.
	wait func() (exitCode int, err error)
}

// commandChild adapts a started exec.Cmd.
func commandChild(cmd *exec.Cmd) *child {
	return &child{
		pid:  cmd.Process.Pid,
		kill: cmd.Process.Kill,
		wait: func() (int, error) {
			err := cmd.Wait()
			return cmd.ProcessState.ExitCode(), err
		},
	}
}

// launch takes a module from binary to started: target, verify, host
// services up, spawn, handshake, Init, Start. sess is the console session a
// per-user module runs in; nil for system modules.
func (r *runner) launch(ctx context.Context, sess *session.Session) (*proc, error) {
	spec := r.spec
	log := r.log

	tgt, err := newTarget(r.sup.Layout, spec.Manifest, sess)
	if err != nil {
		return nil, fmt.Errorf("launch target: %w", err)
	}
	defer tgt.close()

	// 1. Verify before exec — the path that will actually be exec'd, which
	// for a privilege-dropped module is a staged copy. Non-negotiable.
	bin, err := tgt.stageBinary(spec.BinPath)
	if err != nil {
		return nil, fmt.Errorf("staging binary: %w", err)
	}
	if err := r.sup.Verifier.Verify(bin, spec.Manifest); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	// 2. Per-module socket dir, cleaned of any predecessor's leavings.
	sockDir := r.sup.Layout.ModuleRunDir(spec.Manifest.ID)
	if err := os.RemoveAll(sockDir); err != nil {
		return nil, fmt.Errorf("clearing socket dir: %w", err)
	}
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating socket dir: %w", err)
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("handshake token: %w", err)
	}
	token := hex.EncodeToString(nonce[:])

	// 3. Host services for this module.
	hostAddr := filepath.Join(sockDir, "host.sock")
	if runtime.GOOS == "windows" {
		hostAddr = `\\.\pipe\weave-host-` + spec.Manifest.ID + "-" + token[:8]
	}
	hostLis, err := tgt.listenHost(ctx, hostAddr)
	if err != nil {
		return nil, fmt.Errorf("host listener: %w", err)
	}
	// The host server's interceptors use each call's own context; there is
	// no launch context for NewServer to inherit.
	hostSrv := r.sup.Services.NewServer( //nolint:contextcheck // per-call contexts, see above
		spec.Manifest.ID, spec.Manifest.ChannelAddress(), token, spec.Manifest.Subscribes)
	go func() { _ = hostSrv.Serve(hostLis) }()

	fail := func(err error) (*proc, error) {
		hostSrv.Stop()
		return nil, err
	}

	// 4. Spawn with the handshake environment and dropped privilege.
	if err := tgt.prepareSocketDir(sockDir, hostAddr); err != nil {
		return fail(fmt.Errorf("socket dir permissions: %w", err))
	}
	// Sinks, not pipes: os/exec's own copier goroutines feed these and
	// cmd.Wait waits for them to finish, so Wait is safe to call
	// concurrently. Reading StdoutPipe/StderrPipe alongside Wait is the
	// documented os/exec race (Wait closes the pipes mid-read), which lost
	// module crash forensics and produced spurious "exited before
	// handshake" reports.
	firstLine := make(chan string, 1)
	ch, err := tgt.start(bin, []string{
		fmt.Sprintf("%s=%d", handshake.EnvProtocolMin, r.sup.Window.Min),
		fmt.Sprintf("%s=%d", handshake.EnvProtocolMax, r.sup.Window.Max),
		handshake.EnvToken + "=" + token,
		handshake.EnvHostAddr + "=" + hostAddr,
		handshake.EnvSocketDir + "=" + sockDir,
	}, &lineCapture{ch: firstLine, max: 1 << 16}, &lineLog{log: log})
	if err != nil {
		return fail(err)
	}
	job, err := postSpawn(ch.pid)
	if err != nil {
		_ = ch.kill()
		_, _ = ch.wait()
		return fail(fmt.Errorf("process containment: %w", err))
	}

	exited := make(chan error, 1)
	exitCode := make(chan int, 1)
	go func() {
		code, err := ch.wait()
		exitCode <- code
		exited <- err
	}()

	cleanupProc := func(err error) (*proc, error) {
		killProc(ch, job)
		closeJob(job)
		hostSrv.Stop()
		return nil, err
	}

	var raw string
	select {
	case raw = <-firstLine:
	case code := <-exitCode:
		werr := <-exited
		closeJob(job)
		hostSrv.Stop()
		if code == handshake.ExitProtocolUnsupported {
			return nil, errProtocolUnsupported
		}
		return nil, fmt.Errorf("module exited before handshake: %w", werr)
	case <-time.After(r.sup.launchTimeout()):
		return cleanupProc(errHandshakeTimeout)
	case <-ctx.Done():
		return cleanupProc(ctx.Err())
	}

	line, err := handshake.Parse(raw)
	if err != nil {
		return cleanupProc(err)
	}
	if !r.sup.Window.Contains(line.Protocol) {
		return cleanupProc(fmt.Errorf("module claimed protocol %d %w [%d,%d]",
			line.Protocol, errOutsideWindow, r.sup.Window.Min, r.sup.Window.Max))
	}

	// 6. Dial and Init.
	conn, err := ipc.GRPCClient(line.Network, line.Addr)
	if err != nil {
		return cleanupProc(err)
	}
	client := agentv1.NewModuleServiceClient(conn)

	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	initResp, err := client.Init(initCtx, &agentv1.InitRequest{
		Protocol:                line.Protocol,
		ModuleId:                spec.Manifest.ID,
		Capabilities:            r.sup.capabilityList(),
		Config:                  spec.Config,
		Privilege:               privilegeLevel(spec.Manifest),
		WatchdogIntervalSeconds: uint32(r.sup.watchdogInterval().Seconds()),
	})
	if err != nil {
		conn.Close()
		return cleanupProc(fmt.Errorf("init: %w", err))
	}

	// Runtime confirmation of requirements. The manifest gated launch;
	// a module declaring more at runtime than it manifests is refused.
	var missing []string
	for _, c := range initResp.GetRequires() {
		if _, ok := r.sup.Caps[c.GetName()]; !ok {
			missing = append(missing, c.GetName())
		}
	}
	if len(missing) > 0 {
		conn.Close()
		return cleanupProc(fmt.Errorf("%w: %v", errRequirementsUnmet, missing))
	}

	startCtx, cancelStart := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStart()
	if _, err := client.Start(startCtx, &agentv1.StartRequest{}); err != nil {
		conn.Close()
		return cleanupProc(fmt.Errorf("start: %w", err))
	}

	return &proc{
		child:    ch,
		conn:     conn,
		client:   client,
		hostSrv:  hostSrv,
		line:     line,
		initResp: initResp,
		job:      job,
		exited:   exited,
	}, nil
}

// stop winds a proc down: Stop with drain deadline, Shutdown, then kill
// after grace. Stop and Shutdown get separate deadlines so a slow drain
// cannot starve the Shutdown call of its own budget.
//
// ctx is the run context, already cancelled when stop is called: the stop
// and shutdown calls keep its values but not its cancellation, or they would
// fail before reaching the module.
func (p *proc) stop(ctx context.Context, log logger) {
	ctx = context.WithoutCancel(ctx)
	stopCtx, stopCancel := context.WithTimeout(ctx, 15*time.Second)
	if _, err := p.client.Stop(stopCtx, &agentv1.StopRequest{DeadlineSeconds: 10}); err != nil {
		log.Warn("module stop failed", "err", err)
	}
	stopCancel()
	shutCtx, shutCancel := context.WithTimeout(ctx, 5*time.Second)
	if _, err := p.client.Shutdown(shutCtx, &agentv1.ShutdownRequest{}); err != nil {
		log.Warn("module shutdown failed", "err", err)
	}
	shutCancel()
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		log.Warn("module did not exit after shutdown; killing")
		killProc(p.child, p.job)
		<-p.exited
	}
	p.teardown()
}

// kill hard-stops the process.
func (p *proc) kill() {
	killProc(p.child, p.job)
	<-p.exited
	p.teardown()
}

func (p *proc) teardown() {
	p.conn.Close()
	p.hostSrv.Stop()
	closeJob(p.job)
}

func privilegeLevel(m *manifest.Manifest) agentv1.PrivilegeLevel {
	switch m.Privilege {
	case manifest.PrivilegeSystem:
		return agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_SYSTEM
	case manifest.PrivilegeUser:
		return agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_USER
	default:
		return agentv1.PrivilegeLevel_PRIVILEGE_LEVEL_SERVICE
	}
}

// logger is the slog subset launch/stop need; keeps testing simple.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// lineCapture is an io.Writer sink for a module's stdout that reports the
// first line (the handshake) on ch and discards the rest. Bounded by max
// bytes so a module that floods stdout without a newline can't grow the
// buffer without limit — it reports an error line instead.
type lineCapture struct {
	ch  chan<- string
	max int

	mu   sync.Mutex
	buf  []byte
	done bool
}

func (w *lineCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return len(p), nil // handshake seen; drain the rest.
	}
	w.buf = append(w.buf, p...)
	if i := bytes.IndexByte(w.buf, '\n'); i >= 0 {
		w.emit(string(w.buf[:i]))
		return len(p), nil
	}
	if w.max > 0 && len(w.buf) > w.max {
		w.emit("") // over the cap with no newline: signal a bad handshake.
	}
	return len(p), nil
}

func (w *lineCapture) emit(line string) {
	w.done = true
	w.buf = nil
	select {
	case w.ch <- line:
	default:
	}
}

// lineLog is an io.Writer sink for a module's stderr that logs each
// complete line to core, attributed. A trailing partial line is flushed
// when the writer is closed by os/exec's copier finishing.
type lineLog struct {
	log *slog.Logger
	buf []byte
}

func (w *lineLog) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.log.Info("module stderr", "line", string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}
