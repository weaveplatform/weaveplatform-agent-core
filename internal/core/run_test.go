package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/controlsock"
	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/identity"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// recorder keeps log lines so a test can assert on what Run reported for
// the paths that warn rather than fail.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.lines = append(r.lines, string(p))
	r.mu.Unlock()
	return len(p), nil
}

func (r *recorder) has(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lines {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// stateDir is short: the control socket lives under it, and macOS caps
// sun_path at 104 bytes.
func stateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wvcore-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// isolate gives each Run its own control pipe on Windows (the layout's is
// machine-wide and packages test in parallel) and a fixed capability set, so
// whether the test host is itself a VM guest cannot change the run.
func isolate(t *testing.T, caps capability.Set) {
	t.Helper()
	oldProbe, oldAddr := probeCapabilities, controlAddr
	probeCapabilities = func(capability.Channel) capability.Set { return caps }
	controlAddr = func(l layout.Layout) string {
		if runtime.GOOS == "windows" {
			return `\\.\pipe\weave-core-test-` + filepath.Base(l.StateDir)
		}
		return l.ControlSocket()
	}
	t.Cleanup(func() { probeCapabilities, controlAddr = oldProbe, oldAddr })
}

func baseCaps() capability.Set {
	return capability.Set{"platform.osinfo": {"os": runtime.GOOS}}
}

func writeManifest(t *testing.T, dir string, m manifest.Manifest) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.manifest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testManifest(id string, caps ...string) manifest.Manifest {
	return manifest.Manifest{
		Schema: 1, ID: id, Version: "1.0.0", Protocol: 1,
		Zone: "A", Privilege: manifest.PrivilegeService, Session: manifest.SessionSystem,
		Platforms:    []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Capabilities: caps,
	}
}

func otherOS() string {
	if runtime.GOOS == "linux" {
		return "windows"
	}
	return "linux"
}

// runUntilReady runs core, waits for the readiness marker, then stops it
// and returns Run's result.
func runUntilReady(t *testing.T, opts Options) error {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv(envReadyFile, ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	deadline := time.After(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned before ready: %v", err)
		case <-deadline:
			t.Fatal("core never signalled ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Stop only once the control service answers: cancelling before its
	// gRPC server is serving races GracefulStop against Serve, and that
	// shutdown race is not what these tests are about.
	client, conn, err := controlsock.Dial(controlAddr(layout.Resolve(opts.StateDir)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for {
		sctx, scancel := context.WithTimeout(context.Background(), time.Second)
		_, err := client.Status(sctx, &controlv1.StatusRequest{})
		scancel()
		if err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("control service never answered: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context ended")
		return nil
	}
}

func rootKeyJSON(t *testing.T, keyID string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": keyID, "public_key": base64.StdEncoding.EncodeToString(pub),
	})
	return b, pub
}

// A full run to readiness and back: modules are discovered (flat and
// versioned layouts), gated or skipped as the host dictates, the channel
// root key is taken from the build.
func TestRunReachesReadyAndStops(t *testing.T) {
	dir := stateDir(t)
	isolate(t, baseCaps())
	rec := &recorder{}

	mods := filepath.Join(dir, "modules")
	// Flat layout, with a config document. Gated on a capability no host
	// has, so nothing is exec'd.
	writeManifest(t, filepath.Join(mods, "gated"), testManifest("gated", "never.present"))
	writeFile(t, filepath.Join(mods, "gated", exe("gated")), "bin")
	writeFile(t, filepath.Join(mods, "gated", "config.json"), "{}")
	// Versioned layout: `current` names the active version directory.
	ver := filepath.Join(mods, "versioned", "versions", "2.0.0")
	writeManifest(t, ver, testManifest("versioned", "never.present"))
	writeFile(t, filepath.Join(ver, exe("module")), "bin")
	writeFile(t, filepath.Join(mods, "versioned", "current"), "2.0.0\n")
	// A second directory claiming an id already registered.
	writeManifest(t, filepath.Join(mods, "dup"), testManifest("gated", "never.present"))
	writeFile(t, filepath.Join(mods, "dup", exe("gated")), "bin")
	// Built for another OS.
	foreign := testManifest("foreign")
	foreign.Platforms = []manifest.Platform{{OS: otherOS(), Arch: "amd64"}}
	writeManifest(t, filepath.Join(mods, "foreign"), foreign)
	writeFile(t, filepath.Join(mods, "foreign", exe("foreign")), "bin")
	// Noise discovery must step over.
	writeFile(t, filepath.Join(mods, "stray-file"), "")
	if err := os.MkdirAll(filepath.Join(mods, "no-manifest"), 0o755); err != nil {
		t.Fatal(err)
	}

	rootJSON, _ := rootKeyJSON(t, "root")
	old := embeddedRootPub
	embeddedRootPub = rootJSON
	t.Cleanup(func() { embeddedRootPub = old })

	err := runUntilReady(t, Options{
		StateDir:       dir,
		PolicyInterval: time.Hour,
		RootPubPath:    filepath.Join(dir, "ignored-in-release.pub"),
		Log:            slog.New(slog.NewTextHandler(rec, nil)),
	})
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	for _, want := range []string{
		"core starting",
		"does not support this host",
		"already registered",
		"control socket up",
		"core stopping",
	} {
		if !rec.has(want) {
			t.Errorf("log lacks %q", want)
		}
	}
	if !allowRootPubOverride && !rec.has("ignoring --manifest-root-pub") {
		t.Error("release build did not say it ignored the root key override")
	}
}

// With nothing configured — no modules, no policy file, no root key, no
// logger — core still comes up, and says what it is running without.
func TestRunBareMinimum(t *testing.T) {
	dir := stateDir(t)
	isolate(t, baseCaps())
	old := slog.Default()
	rec := &recorder{}
	slog.SetDefault(slog.New(slog.NewTextHandler(rec, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	if err := runUntilReady(
		t,
		Options{StateDir: dir, ModulesDir: filepath.Join(dir, "absent")},
	); err != nil {
		t.Fatalf("Run = %v", err)
	}
	for _, want := range []string{"no modules found", "channel installs are disabled"} {
		if !rec.has(want) {
			t.Errorf("log lacks %q", want)
		}
	}
}

// A hypervisor channel the probe reports is connected for the core's
// lifetime; one that cannot be opened is reported and core runs on without
// it rather than failing to start.
func TestRunHypervisorChannel(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "channel")
	writeFile(t, dev, "")
	failed := []string{"could not connect"}
	if runtime.GOOS == "windows" {
		// Windows falls back to fixed candidates after the probed device,
		// including \\.\COM2, which a CI VM may well have. Either outcome
		// is correct there; what matters is that core comes up regardless.
		failed = append(failed, "hypervisor channel connected")
	}
	for name, c := range map[string]struct {
		device string
		want   []string
	}{
		"connects":       {dev, []string{"hypervisor channel connected"}},
		"cannot connect": {filepath.Join(t.TempDir(), "absent"), failed},
	} {
		t.Run(name, func(t *testing.T) {
			caps := baseCaps()
			caps["hypervisor.channel"] = map[string]string{"device": c.device}
			isolate(t, caps)
			rec := &recorder{}
			err := runUntilReady(t, Options{
				StateDir: stateDir(t),
				Log:      slog.New(slog.NewTextHandler(rec, nil)),
			})
			if err != nil {
				t.Fatalf("Run = %v", err)
			}
			if !slices.ContainsFunc(c.want, rec.has) {
				t.Fatalf("log lacks any of %q", c.want)
			}
		})
	}
}

// Every startup failure must stop Run with a reason, before the control
// socket would advertise a core that is not really there.
func TestRunStartupFailures(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("state dir", func(t *testing.T) {
		isolate(t, baseCaps())
		file := filepath.Join(t.TempDir(), "file")
		writeFile(t, file, "")
		err := Run(
			context.Background(),
			Options{StateDir: filepath.Join(file, "state"), Log: quiet},
		)
		if err == nil || !strings.Contains(err.Error(), "preparing state directories") {
			t.Fatalf("Run = %v", err)
		}
	})

	t.Run("store", func(t *testing.T) {
		isolate(t, baseCaps())
		dir := stateDir(t)
		if err := os.MkdirAll(filepath.Join(dir, "store.key"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := Run(context.Background(), Options{StateDir: dir, Log: quiet})
		if err == nil || !strings.Contains(err.Error(), "opening store") {
			t.Fatalf("Run = %v", err)
		}
	})

	// Identity state sealed under a master key that is then lost cannot be
	// read back; core must not carry on with a fresh identity silently
	// overwriting the old one.
	t.Run("identity", func(t *testing.T) {
		isolate(t, baseCaps())
		dir := stateDir(t)
		st, err := store.Open(dir, keyprotect.New())
		if err != nil {
			t.Fatal(err)
		}
		p := &identity.Provider{Log: quiet, Store: st}
		if err := p.Init(); err != nil {
			t.Fatal(err)
		}
		st.Close()
		if err := os.Remove(filepath.Join(dir, "store.key")); err != nil {
			t.Fatal(err)
		}
		err = Run(context.Background(), Options{StateDir: dir, Log: quiet})
		if err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("Run = %v", err)
		}
	})

	t.Run("modules", func(t *testing.T) {
		isolate(t, baseCaps())
		dir := stateDir(t)
		writeManifest(t, filepath.Join(dir, "modules", "nobin"), testManifest("nobin"))
		err := Run(context.Background(), Options{StateDir: dir, Log: quiet})
		if err == nil || !strings.Contains(err.Error(), "no binary found") {
			t.Fatalf("Run = %v", err)
		}
	})

	t.Run("root key", func(t *testing.T) {
		isolate(t, baseCaps())
		old := embeddedRootPub
		embeddedRootPub = []byte("not a key")
		t.Cleanup(func() { embeddedRootPub = old })
		err := Run(context.Background(), Options{StateDir: stateDir(t), Log: quiet})
		if err == nil || !strings.Contains(err.Error(), "manifest root key") {
			t.Fatalf("Run = %v", err)
		}
	})

	t.Run("control socket", func(t *testing.T) {
		isolate(t, baseCaps())
		bad := filepath.Join(t.TempDir(), "absent", "control.sock")
		controlAddr = func(layout.Layout) string { return bad }
		err := Run(context.Background(), Options{StateDir: stateDir(t), Log: quiet})
		if err == nil || !strings.Contains(err.Error(), "control socket") {
			t.Fatalf("Run = %v", err)
		}
	})
}

func TestManifestRootKey(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	embedded, embeddedPub := rootKeyJSON(t, "root")
	override, overridePub := rootKeyJSON(t, "root")
	path := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(path, override, 0o600); err != nil {
		t.Fatal(err)
	}

	if k, err := manifestRootKey(quiet, nil, "", false); k != nil || err != nil {
		t.Errorf("nothing configured = %v, %v", k, err)
	}
	if k, err := manifestRootKey(quiet, []byte(" \n"), "", false); k != nil || err != nil {
		t.Errorf("blank embedded key = %v, %v", k, err)
	}
	if k, err := manifestRootKey(quiet, embedded, "", false); err != nil || !k.Equal(embeddedPub) {
		t.Errorf("embedded = %v, %v", k, err)
	}
	// Release: the override is refused and the embedded anchor stands.
	if k, err := manifestRootKey(
		quiet,
		embedded,
		path,
		false,
	); err != nil ||
		!k.Equal(embeddedPub) {
		t.Errorf("release with override = %v, %v", k, err)
	}
	// Dev: the override replaces it.
	if k, err := manifestRootKey(quiet, embedded, path, true); err != nil || !k.Equal(overridePub) {
		t.Errorf("dev with override = %v, %v", k, err)
	}
	if _, err := manifestRootKey(
		quiet,
		nil,
		filepath.Join(t.TempDir(), "absent"),
		true,
	); err == nil ||
		!strings.Contains(err.Error(), "reading manifest root key") {
		t.Errorf("dev with missing override = %v", err)
	}
	if _, err := manifestRootKey(quiet, []byte("{"), "", false); err == nil {
		t.Error("garbage key accepted")
	}
}

func TestRefuseUnverified(t *testing.T) {
	if err := refuseUnverified.Verify(
		"/m",
		nil,
	); err == nil ||
		!strings.Contains(err.Error(), "/m") {
		t.Fatalf("Verify = %v", err)
	}
}

func TestDiscoverModules(t *testing.T) {
	t.Run("absent dir is empty", func(t *testing.T) {
		specs, err := discoverModules(filepath.Join(t.TempDir(), "absent"))
		if err != nil || specs != nil {
			t.Fatalf("= %v, %v", specs, err)
		}
	})
	// A NUL cannot appear in a path on any OS, so this is an error that is
	// not "does not exist" everywhere. A regular file is not: Windows reports
	// ReadDir on one as path-not-found, which discovery treats as no modules.
	t.Run("unreadable dir", func(t *testing.T) {
		if _, err := discoverModules(filepath.Join(t.TempDir(), "bad\x00dir")); err == nil {
			t.Fatal("listed an unopenable path as a modules dir")
		}
	})
	t.Run("corrupt manifest", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "m", "module.manifest.json"), "{")
		if _, err := discoverModules(
			dir,
		); err == nil ||
			!strings.Contains(err.Error(), "module m") {
			t.Fatalf("= %v", err)
		}
	})
	// A directory where the binary should be is not a binary.
	t.Run("binary is a directory", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("m"))
		if err := os.MkdirAll(filepath.Join(dir, "m", exe("m")), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := discoverModules(
			dir,
		); err == nil ||
			!strings.Contains(err.Error(), "no binary found") {
			t.Fatalf("= %v", err)
		}
	})
	t.Run("id-named binary wins over the fallback", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("m"))
		writeFile(t, filepath.Join(dir, "m", exe("m")), "")
		writeFile(t, filepath.Join(dir, "m", exe("module")), "")
		specs, err := discoverModules(dir)
		if err != nil || len(specs) != 1 {
			t.Fatalf("= %v, %v", specs, err)
		}
		if got := filepath.Base(specs[0].BinPath); got != exe("m") {
			t.Fatalf("picked %s", got)
		}
		if specs[0].Config != nil {
			t.Fatalf("config %q with no config.json", specs[0].Config)
		}
	})
	t.Run("a current naming anything but one version dir is skipped", func(t *testing.T) {
		for _, cur := range []string{"", "..", "../escape", "/abs", `a\b`, "c:d"} {
			dir := t.TempDir()
			// A manifest the escaping path would reach if it were followed.
			writeManifest(t, filepath.Join(dir, "escape"), testManifest("escape"))
			writeFile(t, filepath.Join(dir, "escape", exe("escape")), "")
			writeFile(t, filepath.Join(dir, "m", "current"), cur+"\n")
			specs, err := discoverModules(dir)
			if err != nil {
				t.Fatalf("current %q: %v", cur, err)
			}
			for _, sp := range specs {
				if filepath.Dir(sp.BinPath) != filepath.Join(dir, "escape") {
					t.Fatalf("current %q: followed to %s", cur, sp.BinPath)
				}
			}
		}
	})
}

func TestSignalReadyFailuresAreNotFatal(t *testing.T) {
	rec := &recorder{}
	log := slog.New(slog.NewTextHandler(rec, nil))

	t.Setenv(envReadyFile, filepath.Join(t.TempDir(), "absent", "ready"))
	signalReady(log)
	if !rec.has("writing readiness marker failed") {
		t.Error("unwritable marker not reported")
	}

	// A directory squatting on the marker path cannot be replaced by the
	// rename; the temp file must not be left behind either.
	dir := t.TempDir()
	marker := filepath.Join(dir, "ready")
	writeFile(t, filepath.Join(marker, "occupied"), "")
	t.Setenv(envReadyFile, marker)
	signalReady(log)
	if !rec.has("publishing readiness marker failed") {
		t.Error("failed publish not reported")
	}
	if _, err := os.Stat(marker + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp marker left behind: %v", err)
	}
}

// The configured channel reaches the probe. One core cannot honour reaches it
// as ChannelNone with an error logged, and core still comes up: fail closed for
// the channel, not for core.
func TestRunChannelConfiguration(t *testing.T) {
	valid := map[string]string{"linux": "vsock:2010", "windows": "hvsocket:2010"}[runtime.GOOS]
	if valid == "" {
		valid = "virtio-serial"
	}
	for name, c := range map[string]struct {
		in      string
		want    string
		wantLog string
	}{
		"default":    {"", "auto", ""},
		"configured": {valid, valid, ""},
		"refused":    {"carrier-pigeon:1", "none", "hypervisor channel disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			isolate(t, baseCaps())
			var got capability.Channel
			probeCapabilities = func(ch capability.Channel) capability.Set {
				got = ch
				return baseCaps()
			}
			rec := &recorder{}
			err := runUntilReady(t, Options{
				StateDir: stateDir(t),
				Channel:  c.in,
				Log:      slog.New(slog.NewTextHandler(rec, nil)),
			})
			if err != nil {
				t.Fatalf("Run = %v", err)
			}
			if got.String() != c.want {
				t.Errorf("probe got channel %q, want %q", got, c.want)
			}
			if c.wantLog != "" && !rec.has(c.wantLog) {
				t.Errorf("log lacks %q", c.wantLog)
			}
		})
	}
}

// A socket channel is listened on, not opened. Whether the listen succeeds
// depends on the test host having AF_VSOCK; either way core says which, and
// comes up. vsock everywhere: on Windows it is refused before the HvSocket
// path would register a service under HKLM, which a test must not do.
func TestRunSocketChannel(t *testing.T) {
	caps := baseCaps()
	caps["hypervisor.channel"] = map[string]string{"kind": "vsock", "port": "52010"}
	isolate(t, caps)
	rec := &recorder{}
	if err := runUntilReady(t, Options{
		StateDir: stateDir(t),
		Log:      slog.New(slog.NewTextHandler(rec, nil)),
	}); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if !rec.has("hypervisor channel listening") && !rec.has("could not connect") {
		t.Fatal("log says neither that the channel is listening nor why not")
	}
}
