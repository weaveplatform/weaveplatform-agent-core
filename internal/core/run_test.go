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
	"github.com/weaveplatform/weaveplatform-agent-core/internal/provision"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/transport"
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
	oldProbe, oldAddr, oldProv := probeCapabilities, controlAddr, provisionAnchor
	probeCapabilities = func(capability.Channel) capability.Set { return caps }
	// A test core never installs a trust anchor on the machine running it.
	provisionAnchor = func(context.Context, *slog.Logger, string) {}
	controlAddr = func(l layout.Layout) string {
		if runtime.GOOS == "windows" {
			return `\\.\pipe\weave-core-test-` + filepath.Base(l.StateDir)
		}
		return l.ControlSocket()
	}
	t.Cleanup(
		func() { probeCapabilities, controlAddr, provisionAnchor = oldProbe, oldAddr, oldProv },
	)
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
	_, stop := startCore(t, opts)
	return stop()
}

// startCore runs core until it is ready and its control service answers, and
// returns a client and a stop that ends the run and returns Run's result.
func startCore(t *testing.T, opts Options) (controlv1.ControlServiceClient, func() error) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv(envReadyFile, ready)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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
	t.Cleanup(func() { conn.Close() })
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
	return client, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			t.Fatal("Run did not return after its context ended")
			return nil
		}
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
	// A directory holding another module's id: invalid, and the rest start.
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
		"does not match its directory",
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

	// A modules directory core cannot read is a broken install, not an
	// empty one. A NUL cannot appear in a path on any OS, so this fails as
	// something other than "does not exist" everywhere.
	t.Run("modules dir", func(t *testing.T) {
		isolate(t, baseCaps())
		dir := stateDir(t)
		err := Run(context.Background(), Options{
			StateDir: dir, ModulesDir: filepath.Join(dir, "bad\x00dir"), Log: quiet,
		})
		if err == nil || !strings.Contains(err.Error(), "reading modules dir") {
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

func TestModuleDirs(t *testing.T) {
	if names, err := moduleDirs(filepath.Join(t.TempDir(), "absent")); err != nil || names != nil {
		t.Fatalf("absent dir = %v, %v", names, err)
	}
	// See the "modules dir" start-up failure for why a NUL.
	if _, err := moduleDirs(filepath.Join(t.TempDir(), "bad\x00dir")); err == nil {
		t.Fatal("listed an unopenable path as a modules dir")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "stray-file"), "")
	writeFile(t, filepath.Join(dir, "b", "x"), "")
	writeFile(t, filepath.Join(dir, "a", "x"), "")
	if names, err := moduleDirs(dir); err != nil || !slices.Equal(names, []string{"a", "b"}) {
		t.Fatalf("= %v, %v", names, err)
	}
}

func TestLoadModule(t *testing.T) {
	invalid := func(t *testing.T, dir, name, want string) {
		t.Helper()
		ent, ok := loadModule(dir, name)
		if !ok || !strings.Contains(ent.invalid, want) {
			t.Fatalf("= %+v, %v; want invalid with %q", ent, ok, want)
		}
	}
	t.Run("not a module", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "file"), "")
		if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"absent", "file", "empty"} {
			if ent, ok := loadModule(dir, name); ok {
				t.Errorf("%s: = %+v", name, ent)
			}
		}
	})
	t.Run("corrupt manifest", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "m", "module.manifest.json"), "{")
		invalid(t, dir, "m", "manifest")
	})
	t.Run("id does not match the directory", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("other"))
		invalid(t, dir, "m", `manifest id "other" does not match its directory "m"`)
	})
	// A directory where the binary should be is not a binary.
	t.Run("binary is a directory", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("m"))
		if err := os.MkdirAll(filepath.Join(dir, "m", exe("m")), 0o755); err != nil {
			t.Fatal(err)
		}
		invalid(t, dir, "m", "no binary found")
	})
	t.Run("config is a directory", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("m"))
		writeFile(t, filepath.Join(dir, "m", exe("m")), "")
		if err := os.MkdirAll(filepath.Join(dir, "m", "config.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		invalid(t, dir, "m", "config.json unreadable")
	})
	t.Run("id-named binary wins over the fallback", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, filepath.Join(dir, "m"), testManifest("m"))
		writeFile(t, filepath.Join(dir, "m", exe("m")), "a")
		writeFile(t, filepath.Join(dir, "m", exe("module")), "b")
		ent, ok := loadModule(dir, "m")
		if !ok || ent.invalid != "" || ent.unsettled {
			t.Fatalf("= %+v, %v", ent, ok)
		}
		if got := filepath.Base(ent.spec.BinPath); got != exe("m") {
			t.Fatalf("picked %s", got)
		}
		if ent.spec.Config != nil {
			t.Fatalf("config %q with no config.json", ent.spec.Config)
		}
		// sha256("a")
		if ent.spec.Digest != "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" {
			t.Fatalf("digest %s", ent.spec.Digest)
		}
	})
	t.Run("versioned", func(t *testing.T) {
		dir := t.TempDir()
		ver := filepath.Join(dir, "m", "versions", "2.0.0")
		writeManifest(t, ver, testManifest("m"))
		writeFile(t, filepath.Join(ver, exe("m")), "")
		writeFile(t, filepath.Join(ver, "config.json"), `{"a":1}`)
		writeFile(t, filepath.Join(dir, "m", "current"), "2.0.0\n")
		ent, ok := loadModule(dir, "m")
		if !ok || ent.invalid != "" || filepath.Dir(ent.spec.BinPath) != ver ||
			string(ent.spec.Config) != `{"a":1}` {
			t.Fatalf("= %+v, %v", ent, ok)
		}
		writeFile(t, filepath.Join(dir, "m", "current"), "3.0.0\n")
		invalid(t, dir, "m", "current names a version with no manifest: 3.0.0")
	})
	t.Run("a current naming anything but one version dir is invalid", func(t *testing.T) {
		for _, cur := range []string{"", "..", "../escape", "/abs", `a\b`, "c:d"} {
			dir := t.TempDir()
			// A manifest the escaping path would reach if it were followed.
			writeManifest(t, filepath.Join(dir, "escape"), testManifest("escape"))
			writeFile(t, filepath.Join(dir, "escape", exe("escape")), "")
			writeFile(t, filepath.Join(dir, "m", "current"), cur+"\n")
			ent, ok := loadModule(dir, "m")
			if !ok || !strings.Contains(ent.invalid, "current does not name a version directory") {
				t.Fatalf("current %q: = %+v, %v", cur, ent, ok)
			}
		}
	})
}

func TestStableDigest(t *testing.T) {
	if _, _, err := stableDigest(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("digest of a missing file")
	}
	// Readable by stat but not by open: a directory.
	if _, _, err := stableDigest(t.TempDir()); err == nil {
		t.Fatal("digest of a directory")
	}
	p := filepath.Join(t.TempDir(), "bin")
	writeFile(t, p, "x")
	if d, settled, err := stableDigest(p); err != nil || !settled || d == "" {
		t.Fatalf("= %q, %v, %v", d, settled, err)
	}
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

// A running core picks up a module installed after it started, through each
// trigger: ControlService.Reload (which answers with what it did), the reload
// channel SIGHUP feeds, and the periodic rescan.
func TestRunReloadsModules(t *testing.T) {
	dir := stateDir(t)
	isolate(t, baseCaps())
	old := watchDir
	watchDir = func(context.Context, *slog.Logger, string, func()) {}
	t.Cleanup(func() { watchDir = old })
	mods := filepath.Join(dir, "modules")
	reload := make(chan struct{})
	client, stop := startCore(t, Options{
		StateDir: dir,
		Reload:   reload,
		Verifier: supervise.VerifierFunc(func(string, *manifest.Manifest) error { return nil }),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	listed := func(id string) bool {
		resp, err := client.Modules(context.Background(), &controlv1.ModulesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(resp.GetModules(), func(m *controlv1.ModuleStatus) bool {
			return m.GetId() == id
		})
	}
	eventually := func(id string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !listed(id) {
			if time.Now().After(deadline) {
				t.Fatalf("%s never appeared", id)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	writeManifest(t, filepath.Join(mods, "a"), testManifest("a", "never.present"))
	writeFile(t, filepath.Join(mods, "a", exe("a")), "a")
	writeFile(t, filepath.Join(mods, "broken", "module.manifest.json"), "{")
	resp, err := client.Reload(context.Background(), &controlv1.ReloadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp.GetAdded(), []string{"a"}) || len(resp.GetInvalid()) != 1 ||
		resp.GetInvalid()[0].GetId() != "broken" {
		t.Fatalf("reload = %v", resp)
	}

	writeManifest(t, filepath.Join(mods, "b"), testManifest("b", "never.present"))
	writeFile(t, filepath.Join(mods, "b", exe("b")), "b")
	reload <- struct{}{}
	eventually("b")

	if err := stop(); err != nil {
		t.Fatalf("Run = %v", err)
	}
}

// With a rescan period and no other trigger, core still finds a new module.
func TestRunRescansModules(t *testing.T) {
	dir := stateDir(t)
	isolate(t, baseCaps())
	old := watchDir
	watchDir = func(context.Context, *slog.Logger, string, func()) {}
	t.Cleanup(func() { watchDir = old })
	client, stop := startCore(t, Options{
		StateDir:     dir,
		ModuleRescan: 50 * time.Millisecond,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	mods := filepath.Join(dir, "modules")
	writeManifest(t, filepath.Join(mods, "a"), testManifest("a", "never.present"))
	writeFile(t, filepath.Join(mods, "a", exe("a")), "a")
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Modules(context.Background(), &controlv1.ModulesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.GetModules()) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the rescan never found the module")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := stop(); err != nil {
		t.Fatalf("Run = %v", err)
	}
}

// A failing reload reaches the client as an error, not an empty answer.
func TestReloadFails(t *testing.T) {
	h := newHarness(t)
	h.rec.dir = filepath.Join(h.dir, "bad\x00dir")
	if _, err := h.rec.reload(context.Background()); err == nil {
		t.Fatal("reload of an unreadable directory answered")
	}
}

// Core installs the channel anchor from a provisioning volume before the
// channel loads it, at --channel-pub when given and the platform path when not.
func TestRunProvisionsTheChannelAnchor(t *testing.T) {
	vol := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(vol, "weave", "channel.pub"), base64.StdEncoding.EncodeToString(pub))
	var asked []string
	fromVolume := func(ctx context.Context, log *slog.Logger, anchor string) {
		asked = append(asked, anchor)
		if anchor == transport.DefaultChannelKeyPath() {
			return // never touch the real one
		}
		(&provision.Provisioner{Log: log, AnchorPath: anchor, Volumes: func() ([]string, error) {
			return []string{vol}, nil
		}}).Start(ctx)
	}

	anchor := filepath.Join(t.TempDir(), "weave", "channel.pub")
	for _, path := range []string{anchor, ""} {
		isolate(t, baseCaps())
		provisionAnchor = fromVolume
		if err := runUntilReady(
			t,
			Options{StateDir: stateDir(t), ChannelPubPath: path},
		); err != nil {
			t.Fatalf("Run = %v", err)
		}
	}
	if len(asked) != 2 || asked[0] != anchor || asked[1] != transport.DefaultChannelKeyPath() {
		t.Fatalf("provisioned %q", asked)
	}
	raw, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := transport.ParseChannelKey(raw); err != nil || !got.Equal(pub) {
		t.Fatalf("anchor holds %q", raw)
	}
}
