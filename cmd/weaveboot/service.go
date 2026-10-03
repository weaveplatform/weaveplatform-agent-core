package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/winsvc"
)

// Seams for the service subcommand's tests.
var (
	newManager     = winsvc.NewManager
	restrictDir    = winsvc.RestrictDir
	executable     = os.Executable
	channelKeyDest = winsvc.DefaultChannelKeyPath
	serviceWaits   = winsvc.DefaultWaits
	platformState  = func() string { return platform.Paths().StateDir }
)

const serviceUsage = `usage: weaveboot service <install|uninstall|start|stop|status> [flags]

  install    copy the agent into place, register the WeaveAgent service
             (LocalSystem, automatic start, restart on failure) and,
             with --start, start it; re-running updates it in place
  uninstall  stop and remove the service (files are left in place)
  start      start the service and wait until it is running
  stop       stop the service and wait until it has stopped
  status     print the service state; exit 0 only when running
`

// exitNotRunning mirrors `systemctl is-active`: 3 is "not running", which
// a script can tell apart from a failure to ask (1).
const exitNotRunning = 3

type envFlag []string

func (e *envFlag) String() string     { return strings.Join(*e, ",") }
func (e *envFlag) Set(v string) error { *e = append(*e, v); return nil }

func serviceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, serviceUsage)
		return 2
	}
	verb := args[0]
	switch verb {
	case "install", "uninstall", "start", "stop", "status":
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, serviceUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "weaveboot service: unknown command %q\n\n%s", verb, serviceUsage)
		return 2
	}

	fs := flag.NewFlagSet("weaveboot service "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", winsvc.DefaultName, "service name")
	var (
		installDir, sourceDir, channelKey *string
		start                             *bool
		env                               envFlag
	)
	if verb == "install" {
		installDir = fs.String(
			"install-dir",
			winsvc.DefaultInstallDir(),
			"where the binaries and modules tree are installed",
		)
		sourceDir = fs.String(
			"source-dir",
			"",
			"directory holding the payload to install (default: the directory of this weaveboot)",
		)
		channelKey = fs.String(
			"channel-key",
			"",
			"file holding the host's base64 Ed25519 channel public key, installed at "+channelKeyDest(),
		)
		start = fs.Bool("start", false, "start the service once installed")
		fs.Var(
			&env,
			"env",
			"KEY=VALUE for the service environment, passed on to core (repeatable; replaces the previous set)",
		)
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "weaveboot service %s: unexpected argument %q\n", verb, fs.Arg(0))
		return 2
	}

	m, err := newManager()
	if err != nil {
		fmt.Fprintf(stderr, "weaveboot service %s: %v\n", verb, err)
		return 1
	}
	defer m.Close()

	switch verb {
	case "install":
		err = install(m, *name, *installDir, *sourceDir, *channelKey, *start, env, stdout)
	case "uninstall":
		err = winsvc.Uninstall(m, *name, serviceWaits)
	case "start":
		err = winsvc.Start(m, *name, serviceWaits)
	case "stop":
		err = winsvc.Stop(m, *name, serviceWaits)
	case "status":
		st, qerr := winsvc.Query(m, *name)
		switch {
		case errors.Is(qerr, winsvc.ErrNotInstalled):
			fmt.Fprintln(stdout, "not-installed")
			return exitNotRunning
		case qerr != nil:
			err = qerr
		default:
			fmt.Fprintln(stdout, st)
			if st != winsvc.Running {
				return exitNotRunning
			}
			return 0
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "weaveboot service %s: %v\n", verb, err)
		return 1
	}
	fmt.Fprintf(stdout, "weaveboot service %s: ok\n", verb)
	return 0
}

func install(
	m winsvc.Manager,
	name, installDir, sourceDir, channelKey string,
	start bool,
	env []string,
	out io.Writer,
) error {
	if sourceDir == "" {
		self, err := executable()
		if err != nil {
			return err
		}
		sourceDir = filepath.Dir(self)
	}
	in := winsvc.Installer{
		Manager: m,
		Service: winsvc.Config{
			Name:        name,
			DisplayName: winsvc.DefaultDisplayName,
			Description: winsvc.DefaultDescription,
			Env:         env,
		},
		SourceDir:      sourceDir,
		InstallDir:     installDir,
		StateDir:       stateRoot(env),
		ChannelKey:     channelKey,
		ChannelKeyDest: channelKeyDest(),
		Restrict:       restrictDir,
		Start:          start,
		Waits:          serviceWaits,
		Log:            out,
	}
	return in.Run()
}

// stateRoot is the state root the installed service will use: the platform
// default, unless the service's own environment redirects it. The
// installing shell's WEAVE_STATE_DIR is deliberately ignored — the service
// will not see it, so locking down that directory would protect nothing.
func stateRoot(env []string) string {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); strings.EqualFold(k, layout.EnvStateDir) && v != "" {
			return v
		}
	}
	return platformState()
}
