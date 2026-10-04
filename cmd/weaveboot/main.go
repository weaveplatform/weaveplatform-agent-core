// Command weaveboot supervises core so core can be replaced in place:
// staged, health-gated, with rollback. launchd/systemd/SCM own weaveboot
// only; weaveboot owns core; core owns modules.
//
// On Windows the same binary is the service the SCM runs and the tool that
// registers it (weaveboot service install): one signed binary to ship, and
// the registration is written by the code that has to match it.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/verify"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/weaveboot"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/winsvc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/wlog"
)

// Seams so tests can drive entry without supervising a real core or
// talking to a real SCM.
var (
	bootRun    = weaveboot.Run
	isService  = winsvc.IsService
	runService = winsvc.Run
)

func main() {
	os.Exit(entry(os.Args[1:], os.Stdout, os.Stderr))
}

func entry(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "service" {
		return serviceCmd(args[1:], stdout, stderr)
	}
	// A detection error is treated as "not a service": running
	// interactively under the SCM fails visibly (the SCM times the start
	// out), whereas the reverse would hang a console waiting on an SCM.
	if svc, err := isService(); err == nil && svc {
		code, err := serve(args)
		if !errors.Is(err, winsvc.ErrNotService) {
			return code
		}
	}
	return run(args, stderr)
}

// serve runs weaveboot under the SCM. A stop control cancels the context
// exactly as SIGTERM does on unix, so core gets the same drain.
func serve(args []string) (int, error) {
	code := 0
	err := runService(func(ctx context.Context) error {
		code = boot(ctx, args, io.Discard, true, nil)
		if code != 0 {
			return fmt.Errorf("weaveboot exited with status %d", code)
		}
		return nil
	})
	if err != nil && code == 0 {
		code = 1
	}
	return code, err
}

func run(args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var forward chan os.Signal
	if len(forwardSignals) > 0 {
		forward = make(chan os.Signal, 1)
		signal.Notify(forward, forwardSignals...)
		defer signal.Stop(forward)
	}
	return boot(ctx, args, stderr, false, forward)
}

func boot(
	ctx context.Context,
	args []string,
	stderr io.Writer,
	service bool,
	forward <-chan os.Signal,
) int {
	fs := flag.NewFlagSet("weaveboot", flag.ContinueOnError)
	// Buffered because under the SCM where it should go is only known once
	// --state-dir has been parsed.
	var parseOut bytes.Buffer
	fs.SetOutput(&parseOut)
	stateDir := fs.String("state-dir", "", "override the state directory (also WEAVE_STATE_DIR)")
	perr := fs.Parse(args)
	lay := layout.Resolve(*stateDir)

	out := stderr
	var coreOut io.Writer
	if service {
		// The SCM gives a service no stdout or stderr. Without a file,
		// weaveboot's own log and everything core prints — including why
		// it failed to start — would go nowhere. A log that cannot be
		// opened does not stop the agent: running unlogged beats not
		// running.
		if f, err := openServiceLog(lay.LogDir); err == nil {
			defer f.Close()
			out, coreOut = f, f
		}
	}
	out.Write(parseOut.Bytes())
	if perr != nil {
		if errors.Is(perr, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	log := wlog.New(out, wlog.LevelFromEnv(), "weaveboot")

	// Everything after -- goes to weave-agent; the state dir always does.
	agentArgs := append([]string{"--state-dir", lay.StateDir}, fs.Args()...)
	err := bootRun(ctx, weaveboot.Options{
		Log:        log,
		CoreDir:    filepath.Join(lay.StateDir, "core"),
		AgentArgs:  agentArgs,
		VerifyCore: verify.Core(log),
		Output:     coreOut,
		Forward:    forward,
	})
	if err != nil {
		log.Error("weaveboot failed", "err", err)
		return 1
	}
	return 0
}

// maxServiceLog bounds the service log. One generation is kept: enough to
// see why the previous run ended, without a rotation scheme to maintain.
const maxServiceLog = 10 << 20

func openServiceLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "weaveboot.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxServiceLog {
		os.Rename(path, path+".1")
	}
	return os.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o600,
	) //nolint:gosec // path is under the state root
}
