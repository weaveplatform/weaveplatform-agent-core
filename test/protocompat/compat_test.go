// Package protocompat is the permanent spec §11 fixture: the test that
// matters is not that a module runs — it is that core at protocol N
// accepts a module built against N-1 and cleanly refuses one outside the
// window. The v1/ directory is pinned to protocol-1 tags and never
// deleted; every future protocol adds a directory beside it.
//
// The core side is core's real supervisor, not a stub: the property is
// about what core accepts, so it is checked on the code that ships.
package protocompat

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/core"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// TestEveryWindowMemberHasFixture is the invariant that keeps §11 honest as
// the window moves: for every protocol in core's advertised window there
// must be a pinned vN/ fixture directory, so a bump can never quietly drop
// compat coverage for a protocol core still claims to support.
func TestEveryWindowMemberHasFixture(t *testing.T) {
	for p := core.Window.Min; p <= core.Window.Max; p++ {
		dir := fmt.Sprintf("v%d", p)
		if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
			t.Errorf(
				"core advertises protocol %d but %s/main.go is missing: add the pinned fixture",
				p,
				dir,
			)
		}
	}
}

// buildFixture builds the pinned protocol-1 module OUTSIDE the workspace
// so its go.mod pins, not the checked-out trees, decide what it links.
func buildFixture(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "compat-v1")
	if runtime.GOOS == "windows" {
		// Windows cannot exec a binary without its extension.
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "v1"
	// The fixture's pins are the protocol-1 SDK's module paths,
	// served by the module proxy. A
	// developer GOPRIVATE covering that org would send the fetch to git and
	// fail, so the proxy is forced for this build. An empty value would fall
	// back to `go env -w` settings, hence a pattern that matches nothing.
	const nothing = "nothing.invalid"
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=mod",
		"GOPRIVATE="+nothing, "GONOPROXY="+nothing, "GONOSUMDB="+nothing,
		"GOPROXY=https://proxy.golang.org")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building pinned fixture: %v\n%s", err, out)
	}
	return bin
}

// supervisor is core's supervisor advertising window, with in-memory host
// services and verification switched off: the fixture is unsigned, and
// signing is not the property under test.
func supervisor(t *testing.T, window handshake.Window) *supervise.Supervisor {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// Not t.TempDir(): long test names push unix socket paths past the
	// 104-byte sun_path limit on macOS.
	dir, err := os.MkdirTemp("", "wv-compat-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lay := layout.Resolve(dir)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sup := &supervise.Supervisor{
		Log:    log,
		Window: window,
		Caps:   capability.Probe(),
		Services: &hostserv.Services{
			Log:       log,
			Bus:       eventbus.New(),
			Store:     hostserv.NewMemStore(),
			Policy:    hostserv.NewMemPolicy(),
			Identity:  hostserv.NewStubIdentity(),
			Transport: &hostserv.LogTransport{Log: log},
		},
		Layout: lay,
		Verifier: supervise.VerifierFunc(
			func(string, *manifest.Manifest) error { return nil },
		),
		Backoff: retry.Backoff{
			Initial: 20 * time.Millisecond,
			Max:     50 * time.Millisecond,
			Factor:  2,
		},
		HealthInterval: 100 * time.Millisecond,
		LaunchTimeout:  30 * time.Second,
		StableAfter:    time.Hour,
	}
	sup.SetBaseContext(ctx)
	t.Cleanup(func() {
		cancel()
		sup.Wait()
	})
	return sup
}

func compatManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Schema:    1,
		ID:        "compat",
		Version:   "1.0.0",
		Protocol:  1,
		Zone:      "A",
		Privilege: manifest.PrivilegeService,
		Session:   manifest.SessionSystem,
		Platforms: []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
	}
}

// waitFor polls the one supervised module until pred accepts its status.
func waitFor(
	t *testing.T,
	sup *supervise.Supervisor,
	desc string,
	pred func(supervise.Status) bool,
) supervise.Status {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last supervise.Status
	for time.Now().Before(deadline) {
		if sts := sup.Statuses(); len(sts) == 1 {
			last = sts[0]
			if pred(last) {
				return last
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("module never reached %s; last: %+v", desc, last)
	return supervise.Status{}
}

func TestProtocol1AcceptedInWindow(t *testing.T) {
	bin := buildFixture(t)

	// Current window {1,1} and the future N-1 shape {1,2}: both must
	// accept a protocol-1 module through Init, Start and a healthy poll.
	for _, window := range []handshake.Window{{Min: 1, Max: 1}, {Min: 1, Max: 2}} {
		t.Run(fmt.Sprintf("window=%d-%d", window.Min, window.Max), func(t *testing.T) {
			sup := supervisor(t, window)
			if err := sup.Add(
				supervise.Spec{Manifest: compatManifest(), BinPath: bin},
			); err != nil {
				t.Fatal(err)
			}
			st := waitFor(t, sup, "running and healthy", func(s supervise.Status) bool {
				return s.State == supervise.StateRunning &&
					s.Health.GetStatus() == agentv1.Health_STATUS_HEALTHY
			})
			if st.Protocol != 1 {
				t.Fatalf("negotiated protocol %d, want 1", st.Protocol)
			}
		})
	}
}

func TestProtocol1RefusedOutsideWindow(t *testing.T) {
	bin := buildFixture(t)

	// A core whose window has moved past protocol 1 (the N-3 shape) must
	// be refused cleanly: exit 78, no listen, no crash loop.
	sup := supervisor(t, handshake.Window{Min: 2, Max: 4})
	if err := sup.Add(supervise.Spec{Manifest: compatManifest(), BinPath: bin}); err != nil {
		t.Fatal(err)
	}
	st := waitFor(t, sup, "unsupported-protocol", func(s supervise.Status) bool {
		return s.State == supervise.StateUnsupportedProtocol
	})
	if st.Restarts != 0 || st.PID != 0 {
		t.Fatalf("window [2,4]: refusal was not clean: %+v", st)
	}
}
