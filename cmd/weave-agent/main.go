// Command weave-agent is core: the one authenticated, policied, supervised
// presence on a machine. Everything product-shaped lives in modules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/core"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/verify"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/version"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/wlog"
)

// Seams so tests can drive run without starting a real core.
var (
	coreRun            = core.Run
	newChannelVerifier = verify.NewChannelFromDir
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("weave-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String(
		"state-dir",
		"",
		"override the state directory (dev/tests; also WEAVE_STATE_DIR)",
	)
	modulesDir := fs.String("modules-dir", "", "override the installed-modules directory")
	policyFile := fs.String("policy-file", os.Getenv("WEAVE_POLICY_FILE"),
		"policy set to read and watch (default: policy.json in the state directory)")
	policyInterval := fs.Duration(
		"policy-interval",
		0,
		"how often the policy file is checked for a change (default 30s)",
	)
	manifestURL := fs.String("manifest-url", os.Getenv("WEAVE_MANIFEST_URL"),
		"base URL of the signed channel manifest bundle")
	rootPub := fs.String("manifest-root-pub", os.Getenv("WEAVE_MANIFEST_ROOT_PUB"),
		"path to the manifest root public key (dev/self-hosted)")
	channelDir := fs.String(
		"channel-dir",
		os.Getenv("WEAVE_CHANNEL_DIR"),
		"directory holding a signed channel-manifest bundle to verify modules against (offline installs)",
	)
	channelPub := fs.String(
		"channel-pub",
		os.Getenv("WEAVE_CHANNEL_PUB"),
		"path to the public key a host must prove possession of to drive this guest over the hypervisor channel (default: the platform path)",
	)
	channel := fs.String(
		"channel",
		os.Getenv("WEAVE_CHANNEL"),
		"host channel transport: auto (default), virtio-serial, vsock:<port> (Linux), hvsocket:<port> (Windows) or unix:<absolute path> (containers)",
	)
	rescan := fs.Duration(
		"module-rescan",
		envDuration("WEAVE_MODULE_RESCAN", defaultModuleRescan),
		"how often the modules directory is reread whatever the watch reports; 0 disables (also WEAVE_MODULE_RESCAN)",
	)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.Version)
		return 0
	}

	log := wlog.New(stderr, wlog.LevelFromEnv(), "weave-agent")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	reload := notifyReload(ctx)

	// An offline install — a VM guest, an air-gapped host — has no manifest
	// server to fetch from, so the signed channel manifest ships beside the
	// modules and anchors verification locally. Falling back to the platform
	// verifier when it is absent is safe: those fail closed where there is no
	// signature story (Linux) and check the OS signature where there is.
	verifier := verify.New(log)
	if *channelDir != "" {
		v, err := newChannelVerifier(log, *rootPub, *channelDir)
		if err != nil {
			log.Error("channel-anchored verification unavailable", "err", err)
			return 1
		}
		verifier = v
	}

	err := coreRun(ctx, core.Options{
		StateDir:       *stateDir,
		ModulesDir:     *modulesDir,
		Verifier:       verifier,
		PolicyFile:     *policyFile,
		PolicyInterval: *policyInterval,
		ManifestURL:    *manifestURL,
		RootPubPath:    *rootPub,
		ChannelPubPath: *channelPub,
		Channel:        *channel,
		ModuleRescan:   *rescan,
		Reload:         reload,
		Log:            log,
	})
	if err != nil {
		log.Error("core failed", "err", err)
		return 1
	}
	return 0
}

// defaultModuleRescan is the safety net under the directory watch and SIGHUP:
// a minute is soon enough for a change nothing reported, and rereading a
// handful of module directories that often costs nothing.
const defaultModuleRescan = time.Minute

// envDuration reads a duration setting from the environment, falling back to
// def when it is unset or does not parse — the flag's own parse then reports
// nothing, so a typo in /etc/default/weave-agent costs the setting, not core.
func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
