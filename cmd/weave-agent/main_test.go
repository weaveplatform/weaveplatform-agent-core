package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/core"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/version"
)

func stubCore(t *testing.T, fn func(context.Context, core.Options) error) {
	t.Helper()
	orig := coreRun
	coreRun = fn
	t.Cleanup(func() { coreRun = orig })
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"WEAVE_POLICY_FILE", "WEAVE_MANIFEST_URL", "WEAVE_MANIFEST_ROOT_PUB", "WEAVE_CHANNEL_DIR", "WEAVE_CHANNEL_PUB", "WEAVE_CHANNEL", "WEAVE_MODULE_RESCAN"} {
		t.Setenv(k, "")
	}
}

func TestVersion(t *testing.T) {
	stubCore(t, func(context.Context, core.Options) error {
		t.Fatal("-version must not start core")
		return nil
	})
	var out bytes.Buffer
	if code := run([]string{"-version"}, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(out.String()) != version.Version {
		t.Fatalf("printed %q, want %q", out.String(), version.Version)
	}
}

func TestFlagErrors(t *testing.T) {
	var errOut bytes.Buffer
	if code := run([]string{"-no-such-flag"}, &bytes.Buffer{}, &errOut); code != 2 {
		t.Fatalf("unknown flag exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "no-such-flag") {
		t.Fatalf("stderr does not name the bad flag: %q", errOut.String())
	}
	if code := run([]string{"-h"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("-h exit %d, want 0", code)
	}
}

func TestOptionsReachCore(t *testing.T) {
	clearEnv(t)
	t.Setenv("WEAVE_POLICY_FILE", "/p.json")
	var got core.Options
	stubCore(t, func(ctx context.Context, o core.Options) error {
		if ctx.Err() != nil {
			t.Error("core started with a done context")
		}
		got = o
		return nil
	})
	code := run([]string{
		"-state-dir", "/s", "-modules-dir", "/m", "-policy-interval", "3s",
		"-manifest-url", "https://m.example", "-manifest-root-pub", "/root.pub",
		"-channel-pub", "/chan.pub",
		"-channel", "vsock:2010",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got.StateDir != "/s" || got.ModulesDir != "/m" || got.PolicyInterval != 3*time.Second ||
		got.PolicyFile != "/p.json" ||
		got.ManifestURL != "https://m.example" ||
		got.RootPubPath != "/root.pub" ||
		got.ChannelPubPath != "/chan.pub" ||
		got.Channel != "vsock:2010" {
		t.Fatalf("options not passed through: %+v", got)
	}
	if got.Verifier == nil || got.Log == nil {
		t.Fatal("core started without a verifier or logger")
	}
}

func TestCoreFailureExitsNonZero(t *testing.T) {
	clearEnv(t)
	stubCore(t, func(context.Context, core.Options) error { return errors.New("store locked") })
	var errOut bytes.Buffer
	if code := run(nil, &bytes.Buffer{}, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "store locked") {
		t.Fatalf("failure not logged: %q", errOut.String())
	}
}

// A channel dir with no root key to anchor it must refuse to start rather
// than fall back to a weaker verifier.
func TestChannelDirWithoutRootFailsClosed(t *testing.T) {
	clearEnv(t)
	stubCore(t, func(context.Context, core.Options) error {
		t.Fatal("core started without its channel verifier")
		return nil
	})
	var errOut bytes.Buffer
	if code := run([]string{"-channel-dir", t.TempDir()}, &bytes.Buffer{}, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "channel-anchored verification unavailable") {
		t.Fatalf("stderr: %q", errOut.String())
	}
}

func TestChannelVerifierIsUsed(t *testing.T) {
	clearEnv(t)
	want := supervise.VerifierFunc(
		func(string, *manifest.Manifest) error { return errors.New("channel") },
	)
	origNV := newChannelVerifier
	newChannelVerifier = func(_ *slog.Logger, root, dir string) (supervise.Verifier, error) {
		if root != "/root.pub" || dir != "/chan" {
			t.Errorf("channel verifier got root=%q dir=%q", root, dir)
		}
		return want, nil
	}
	t.Cleanup(func() { newChannelVerifier = origNV })

	var got supervise.Verifier
	stubCore(t, func(_ context.Context, o core.Options) error {
		got = o.Verifier
		return nil
	})
	if code := run(
		[]string{"-channel-dir", "/chan", "-manifest-root-pub", "/root.pub"},
		&bytes.Buffer{},
		&bytes.Buffer{},
	); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got == nil || got.Verify("x", nil).Error() != "channel" {
		t.Fatal("core did not receive the channel verifier")
	}
}

func TestChannelFromEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("WEAVE_CHANNEL", "hvsocket:2010")
	var got core.Options
	stubCore(t, func(_ context.Context, o core.Options) error { got = o; return nil })
	if code := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got.Channel != "hvsocket:2010" {
		t.Fatalf("Channel = %q, want WEAVE_CHANNEL's value", got.Channel)
	}
}

// The rescan period comes from the flag, else WEAVE_MODULE_RESCAN, else a
// minute; a value that does not parse falls back rather than stopping core.
func TestModuleRescanSetting(t *testing.T) {
	for name, c := range map[string]struct {
		env  string
		args []string
		want time.Duration
	}{
		"default":     {"", nil, time.Minute},
		"environment": {"5s", nil, 5 * time.Second},
		"bad env":     {"soon", nil, time.Minute},
		"flag wins":   {"5s", []string{"-module-rescan", "0"}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("WEAVE_MODULE_RESCAN", c.env)
			var got core.Options
			stubCore(t, func(_ context.Context, o core.Options) error { got = o; return nil })
			if code := run(c.args, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if got.ModuleRescan != c.want {
				t.Fatalf("ModuleRescan = %v, want %v", got.ModuleRescan, c.want)
			}
		})
	}
}

// session-exec is dispatched before flags, and never starts core.
func TestSessionExecMode(t *testing.T) {
	stubCore(t, func(context.Context, core.Options) error {
		t.Fatal("session-exec must not start core")
		return nil
	})
	orig := sessionExec
	t.Cleanup(func() { sessionExec = orig })
	var got []string
	sessionExec = func(args []string, _ io.Writer) int {
		got = args
		return 7
	}
	if code := run(
		[]string{supervise.SessionExecCommand, "501", "20", "20", "/opt/mod"},
		&bytes.Buffer{},
		&bytes.Buffer{},
	); code != 7 ||
		!slices.Equal(got, []string{"501", "20", "20", "/opt/mod"}) {
		t.Fatalf("exit %d, args %q", code, got)
	}
}
