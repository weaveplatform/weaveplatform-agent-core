// Package core wires the agent together and runs it. Assembly and the run
// loop only — everything with behaviour lives in its own package.
package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/controlsock"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/identity"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/lifecycle"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/policy"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/transport"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/version"
)

// Window is the protocol range this core accepts. Protocol 1 is current;
// the window widens when protocol 2 ships.
var Window = handshake.Window{Min: 1, Max: 1}

// Seams for Run's tests: the host inventory decides whether core opens a
// hypervisor channel, and the Windows control pipe name is machine-wide, so
// tests substitute both. Nothing but a test writes them.
var (
	probeCapabilities = capability.ProbeWith
	controlAddr       = layout.Layout.ControlSocket
	// watchDir is the modules directory watch; a test of the other reload
	// triggers turns it off so it cannot be the one that fired.
	watchDir = watchModules
)

// errNoVerifier is what refuseUnverified answers for every binary.
var errNoVerifier = errors.New("no verifier configured")

// errNoBinary is a module directory with a manifest and nothing to run.
var errNoBinary = errors.New("manifest present but no binary found")

// refuseUnverified stands in when no verifier is configured.
var refuseUnverified = supervise.VerifierFunc(func(path string, _ *manifest.Manifest) error {
	return fmt.Errorf("%w; refusing to exec %s", errNoVerifier, path)
})

// Options configure a core run.
type Options struct {
	// StateDir overrides the platform layout (dev, tests).
	StateDir string
	// ModulesDir is scanned for installed modules: one subdirectory per
	// module containing module.manifest.json and the module binary.
	// Empty means the layout's modules dir.
	ModulesDir string
	// Verifier authenticates module binaries. Nil refuses everything —
	// core fails closed until the verify milestone wires the real one.
	Verifier supervise.Verifier
	// PolicyFile is the policy set core reads and watches. Empty takes the
	// layout's default (<state>/policy.json).
	PolicyFile string
	// PolicyInterval overrides how often the policy file is checked for a
	// change (zero = policy.DefaultInterval).
	PolicyInterval time.Duration
	// ManifestURL is where the signed channel manifest bundle lives.
	ManifestURL string
	// RootPubPath loads the manifest root public key from a file (dev/
	// self-hosted); release packaging embeds it instead.
	RootPubPath string
	// ChannelPubPath is the Ed25519 public key a host must prove possession
	// of before it may drive this guest over the hypervisor channel. Empty
	// takes the platform default (transport.DefaultChannelKeyPath), which is
	// where a guest image provisions it.
	ChannelPubPath string
	// Channel selects the hypervisor channel transport: "" or "auto" probes
	// for the virtio-serial port, "virtio-serial" forces that probe,
	// "vsock:<port>" (Linux) and "hvsocket:<port>" (Windows) listen for the
	// host on a socket. Socket channels are never inferred — see
	// capability.Channel. A value core cannot honour disables the channel
	// rather than core.
	Channel string
	// ModuleRescan is how often the modules directory is reread whatever
	// else has or has not reported a change. Zero disables it.
	ModuleRescan time.Duration
	// Reload receives a value each time something outside core (SIGHUP)
	// asks for the modules directory to be reread. Nil: nothing does.
	Reload <-chan struct{}
	Log    *slog.Logger
}

// Run starts core and blocks until ctx ends.
func Run(ctx context.Context, opts Options) error {
	// Everything Run starts ends when it returns, on an error path too: a
	// failed start must not leave the reload loop or the watch running.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	lay := layout.Resolve(opts.StateDir)
	if err := lay.Ensure(); err != nil {
		return fmt.Errorf("preparing state directories: %w", err)
	}
	modulesDir := opts.ModulesDir
	if modulesDir == "" {
		modulesDir = lay.ModulesDir
	}

	channel, err := capability.ParseChannel(opts.Channel)
	if err != nil {
		// Fail closed for the channel, not for core: a guest with a mistyped
		// setting is still worth running, but guessing at a transport the
		// host may not be offering is how a channel ends up silently dead.
		log.Error("hypervisor channel disabled", "err", err)
		channel = capability.Channel{Kind: capability.ChannelNone}
	}
	caps := probeCapabilities(channel)
	log.Info("core starting",
		"version", version.Version,
		"protocol_min", Window.Min, "protocol_max", Window.Max,
		"state_dir", lay.StateDir, "modules_dir", modulesDir,
		"capabilities", len(caps))

	verifier := opts.Verifier
	if verifier == nil {
		verifier = refuseUnverified
	}

	st, err := store.Open(lay.StateDir, keyprotect.New())
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	policyFile := opts.PolicyFile
	if policyFile == "" {
		policyFile = lay.PolicyFile()
	}
	policyMgr := &policy.Manager{
		Log:      log,
		Path:     policyFile,
		Interval: opts.PolicyInterval,
		Cache:    st,
	}
	policyMgr.Load(ctx)
	go policyMgr.Run(ctx)

	ident := &identity.Provider{Log: log, Store: st}
	// Init takes no context: the identity is created and persisted once,
	// before anything is served, and must not be half-written by a
	// cancellation.
	if err := ident.Init(); err != nil { //nolint:contextcheck // identity.Provider.Init has no context parameter
		return fmt.Errorf("identity: %w", err)
	}

	// The one table of installed modules: the supervisor writes it; transport
	// delivery, the host channel, RegistryService and ControlService read it.
	modules := registry.New()
	mux := &transport.Mux{Log: log, Queue: st, Registry: modules}
	// The host channel is the only peer: whatever drives this machine from
	// directly outside it. Core owns the single connection; modules address
	// PEER_HYPERVISOR and never touch the wire. Runs for the core lifetime.
	if attrs, ok := caps["hypervisor.channel"]; ok {
		switch err := mux.ConnectHypervisor(ctx, attrs, opts.ChannelPubPath); {
		case err != nil:
			log.Warn(
				"hypervisor channel present but could not connect",
				"channel",
				channel.String(),
				"err",
				err,
			)
		case attrs["port"] != "":
			log.Info("hypervisor channel listening", "kind", attrs["kind"], "port", attrs["port"])
		default:
			log.Info("hypervisor channel connected", "device", attrs["device"])
		}
	}

	services := &hostserv.Services{
		Log:       log,
		Bus:       eventbus.New(),
		Store:     st,
		Policy:    policyMgr,
		Identity:  ident,
		Transport: mux,
		Registry:  modules,
	}

	sup := &supervise.Supervisor{
		Log:      log,
		Window:   Window,
		Caps:     caps,
		Services: services,
		Layout:   lay,
		Verifier: verifier,
		Registry: modules,
		// Ask modules to ping every 10s; a module silent for 20s (two
		// intervals) is restarted as hung. Catches hangs that Health
		// polling, answered on a separate goroutine, would miss.
		WatchdogInterval: 10 * time.Second,
	}
	// Close the watchdog loop: each module's pings reach the supervisor
	// through this seam (set after sup exists to break the construction
	// cycle between services and sup).
	services.Watchdog = sup.Keepalive
	// Modules live on the core run-lifetime context, never on the context
	// of whatever operation (boot loop, control-socket install) spawned
	// them.
	sup.SetBaseContext(ctx)
	sup.SweepOrphans()

	// The lifecycle manager installs where core discovers: --modules-dir
	// moves both, or a channel install would land somewhere no reload looks
	// and the next one would stop it.
	lcmLayout := lay
	lcmLayout.ModulesDir = modulesDir
	lcm := &lifecycle.Manager{
		Log:         log,
		Layout:      lcmLayout,
		Verifier:    verifier,
		Supervisor:  sup,
		ManifestURL: opts.ManifestURL,
		SeqStore:    st,
	}
	rootPub, err := manifestRootKey(log, embeddedRootPub, opts.RootPubPath, allowRootPubOverride)
	if err != nil {
		return err
	}
	if rootPub == nil {
		log.Warn("no manifest root key configured; channel installs are disabled")
	}
	lcm.RootPub = rootPub

	rec := &reconciler{
		log:    log,
		dir:    modulesDir,
		sup:    sup,
		lock:   lcm,
		rescan: opts.ModuleRescan,
	}
	// Start-up is the first reload pass. One module that cannot run is
	// recorded invalid and the rest start; a modules directory core cannot
	// read at all stops core instead. That is a broken install, not an empty
	// one, and a core that came up with no modules would look healthy to
	// weaveboot and systemd while running nothing. A later pass that cannot
	// read it changes nothing and says so.
	diff, err := rec.reconcile() //nolint:contextcheck // modules run on the base context set above
	if err != nil {
		return err
	}
	if len(diff.Added) == 0 && len(diff.Invalid) == 0 {
		log.Warn("no modules found", "dir", modulesDir)
	}
	recDone := make(chan struct{})
	go func() {
		defer close(recDone)
		rec.run(ctx)
	}()
	go watchDir(ctx, log, modulesDir, rec.trigger)
	if opts.Reload != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-opts.Reload:
					if !ok {
						return
					}
					log.Info("module reload requested")
					rec.trigger()
				}
			}
		}()
	}

	ctl := &controlsock.Server{
		Log:        log,
		Supervisor: sup,
		Lifecycle:  lcm,
		Window:     Window,
		Identity:   ident,
		StartedAt:  time.Now(),
		Reloader:   rec.reload,
	}
	ctlErr := make(chan error, 1)
	go func() { ctlErr <- ctl.Serve(ctx, controlAddr(lay)) }()

	// Readiness signal to weaveboot: once modules are registered and the
	// control socket is being served, this core is up. weaveboot promotes a
	// staged core on this signal (health-gated) rather than on a blind
	// uptime timer — a core that reaches here proves it loads and configures.
	signalReady(log)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-ctlErr:
		if err != nil {
			runErr = fmt.Errorf("control socket: %w", err)
		}
	}
	log.Info("core stopping")
	cancel()
	// A pass in flight could Add a module after Wait has taken its list.
	<-recDone
	sup.Wait()
	return runErr
}

// manifestRootKey returns the channel manifest root key, or nil when none is
// configured. The key is baked into release builds (embedded) so the trust
// anchor can't be swapped by pointing core at a file; only dev builds
// (allowOverride) honour --manifest-root-pub.
func manifestRootKey(
	log *slog.Logger,
	embedded []byte,
	overridePath string,
	allowOverride bool,
) (ed25519.PublicKey, error) {
	keyBytes := embedded
	if overridePath != "" {
		if !allowOverride {
			log.Warn("ignoring --manifest-root-pub: release builds use the embedded root key")
		} else {
			data, err := os.ReadFile(overridePath)
			if err != nil {
				return nil, fmt.Errorf("reading manifest root key: %w", err)
			}
			keyBytes = data
		}
	}
	if len(bytes.TrimSpace(keyBytes)) == 0 {
		return nil, nil
	}
	_, raw, err := manifest.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest root key: %w", err)
	}
	return raw, nil
}

// envReadyFile is the path weaveboot asks core to write its readiness
// marker to (weaveboot sets it before exec). Empty when core is run
// directly (dev), in which case signalReady is a no-op. Must match
// weaveboot.EnvReadyFile.
const envReadyFile = "WEAVE_READY_FILE"

// signalReady writes core's version to the readiness marker weaveboot
// watches, atomically (temp + rename). weaveboot cleared any prior marker
// before launch, so its presence means this run reached steady state.
// Failure to write is logged, never fatal — a missing marker only costs
// weaveboot its faster promotion path; it falls back to the uptime timer.
func signalReady(log *slog.Logger) {
	path := os.Getenv(envReadyFile)
	if path == "" {
		return
	}
	// The path comes from weaveboot, which launched this process; it is
	// configuration, not input from anything core serves.
	tmp := path + ".tmp"
	marker := []byte(version.Version + "\n")
	if err := os.WriteFile(tmp, marker, 0o600); err != nil { //nolint:gosec // path set by weaveboot

		log.Warn("writing readiness marker failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil { //nolint:gosec // path set by weaveboot
		log.Warn("publishing readiness marker failed", "err", err)
		_ = os.Remove(tmp) //nolint:gosec // path set by weaveboot
	}
}

// isVersionDir reports whether v names exactly one directory under versions/:
// a `current` file pointing elsewhere (an absolute path, "..", a nested path)
// would make discovery load a manifest and binary from outside the module.
func isVersionDir(v string) bool {
	return v != "" && v != "." && v != ".." && filepath.Base(v) == v &&
		!strings.ContainsAny(v, `/\:`)
}

func binaryCandidates(id string) []string {
	if runtime.GOOS == "windows" {
		return []string{id + ".exe", "module.exe"}
	}
	return []string{id, "module"}
}
