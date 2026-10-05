// Command weavectl is the operator CLI over core's control socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/controlsock"
	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
)

const usage = `weavectl — Weave platform agent control

Usage:
  weavectl [-socket PATH] status                        core status
  weavectl [-socket PATH] modules                       supervised module states
  weavectl [-socket PATH] surfaces                      declared UI surfaces
  weavectl [-socket PATH] install <module> [version]    install from the channel manifest
  weavectl [-socket PATH] install -local <dir>          install from a local directory (dev)
  weavectl [-socket PATH] rollback <module>             flip to the retained previous version
  weavectl [-socket PATH] reload                        reread the modules directory and apply changes
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("weavectl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "control socket path (default: the platform layout's)")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fatal := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "weavectl: "+format+"\n", args...)
		return 1
	}

	cmd := fs.Arg(0)
	if cmd == "" {
		fs.Usage()
		return 2
	}

	addr := *socket
	if addr == "" {
		addr = defaultSocket()
	}

	client, conn, err := controlsock.Dial(addr)
	if err != nil {
		return fatal("connecting to %s: %v", addr, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch cmd {
	case "status":
		st, err := client.Status(ctx, &controlv1.StatusRequest{})
		if err != nil {
			return fatal("status: %v", err)
		}
		fmt.Fprintf(stdout, "core      %s\n", st.GetCoreVersion())
		fmt.Fprintf(
			stdout,
			"protocol  [%d,%d]\n",
			st.GetProtocol().GetMin(),
			st.GetProtocol().GetMax(),
		)
		fmt.Fprintf(stdout, "device    %s\n", st.GetDeviceId())
		fmt.Fprintf(stdout, "enrolled  %v\n", st.GetEnrolled())
		fmt.Fprintf(
			stdout,
			"uptime    %s\n",
			(time.Duration(st.GetUptimeSeconds()) * time.Second).String(),
		)

	case "modules":
		resp, err := client.Modules(ctx, &controlv1.ModulesRequest{})
		if err != nil {
			return fatal("modules: %v", err)
		}
		w := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "MODULE\tADDRESS\tVERSION\tPROTO\tSTATE\tPID\tRESTARTS\tHEALTH")
		for _, m := range resp.GetModules() {
			health := "-"
			if h := m.GetHealth(); h != nil {
				health = h.GetStatus().String()
				if r := h.GetReason(); r != "" {
					health += " (" + r + ")"
				}
			}
			address := m.GetAddress()
			if address == "" {
				address = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%d\t%d\t%s\n",
				m.GetId(), address, m.GetVersion(), m.GetProtocol(), m.GetState(),
				m.GetPid(), m.GetRestarts(), health)
		}
		w.Flush()

	case "surfaces":
		resp, err := client.Surfaces(ctx, &controlv1.SurfacesRequest{})
		if err != nil {
			return fatal("surfaces: %v", err)
		}
		if len(resp.GetModules()) == 0 {
			fmt.Fprintln(stdout, "no surfaces declared")
			return 0
		}
		for _, ms := range resp.GetModules() {
			for _, s := range ms.GetSurfaces() {
				fmt.Fprintf(stdout, "%s/%s  kind=%s  title=%q  (%d bytes)\n",
					ms.GetModuleId(), s.GetId(), s.GetKind(), s.GetTitle(), len(s.GetData()))
			}
		}

	case "install":
		req := &controlv1.InstallRequest{}
		args := fs.Args()[1:]
		if len(args) >= 2 && args[0] == "-local" {
			abs, err := filepath.Abs(args[1])
			if err != nil {
				return fatal("resolving path: %v", err)
			}
			req.LocalPath = abs
		} else if len(args) >= 1 {
			req.ModuleId = args[0]
			if len(args) >= 2 {
				req.Version = args[1]
			}
		} else {
			fs.Usage()
			return 2
		}
		// Install includes the health gate; give it time.
		ictx, icancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer icancel()
		resp, err := client.Install(ictx, req)
		if err != nil {
			return fatal("install: %v", err)
		}
		fmt.Fprintf(stdout, "installed %s\n", resp.GetInstalledVersion())

	case "rollback":
		if fs.Arg(1) == "" {
			fs.Usage()
			return 2
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer rcancel()
		resp, err := client.Rollback(rctx, &controlv1.RollbackRequest{ModuleId: fs.Arg(1)})
		if err != nil {
			return fatal("rollback: %v", err)
		}
		fmt.Fprintf(stdout, "rolled back to %s\n", resp.GetRolledBackTo())

	case "reload":
		// A replace drains the old process before starting the new one.
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer rcancel()
		resp, err := client.Reload(rctx, &controlv1.ReloadRequest{})
		if err != nil {
			return fatal("reload: %v", err)
		}
		printReload(stdout, resp)

	default:
		fs.Usage()
		return 2
	}
	return 0
}

// printReload lists what a reload did, one module per line, and every
// module directory core still cannot run.
func printReload(out io.Writer, resp *controlv1.ReloadResponse) {
	w := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	for _, row := range []struct {
		verb string
		ids  []string
	}{
		{"added", resp.GetAdded()},
		{"removed", resp.GetRemoved()},
		{"replaced", resp.GetReplaced()},
	} {
		for _, id := range row.ids {
			fmt.Fprintf(w, "%s\t%s\n", row.verb, id)
		}
	}
	for _, m := range resp.GetInvalid() {
		fmt.Fprintf(w, "invalid\t%s\t%s\n", m.GetId(), m.GetDetail())
	}
	w.Flush()
	if len(resp.GetAdded())+len(resp.GetRemoved())+len(resp.GetReplaced()) == 0 {
		fmt.Fprintln(out, "no module changes")
	}
}

// defaultSocket is the control socket of a core weaveboot started: the
// platform layout's, or the relocated one when WEAVE_STATE_DIR names a root.
func defaultSocket() string {
	return layout.Resolve("").ControlSocket()
}
