package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/capability"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/retry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// gatedManager is a Manager whose supervisor has no capabilities, so any
// module requiring platform.osinfo is registered as requirements-unmet
// without ever being launched. That reaches every failed-gate path in
// milliseconds and without building a module.
func gatedManager(t *testing.T) *Manager {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	dir, err := os.MkdirTemp("", "wvlg-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lay := layout.Resolve(dir)
	if err := lay.Ensure(); err != nil {
		t.Fatal(err)
	}
	ok := supervise.VerifierFunc(func(string, *manifest.Manifest) error { return nil })
	sup := &supervise.Supervisor{
		Log:    log,
		Window: handshake.Window{Min: 1, Max: 1},
		Caps:   capability.Set{},
		Services: &hostserv.Services{
			Log: log, Bus: eventbus.New(), Store: hostserv.NewMemStore(),
			Policy: hostserv.NewMemPolicy(), Identity: hostserv.NewStubIdentity(),
			Transport: &hostserv.LogTransport{Log: log},
		},
		Layout:   lay,
		Verifier: ok,
		Backoff: retry.Backoff{
			Initial: 20 * time.Millisecond,
			Max:     50 * time.Millisecond,
			Factor:  2,
		},
		StartLimitBurst:  1000,
		StartLimitWindow: time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		sup.Wait()
	})
	sup.SetBaseContext(ctx)
	return &Manager{
		Log: log, Layout: lay, Verifier: ok, Supervisor: sup,
		GateTimeout: 2 * time.Second, GateStable: 100 * time.Millisecond,
	}
}

func testManifest(version string, caps ...string) *manifest.Manifest {
	return &manifest.Manifest{
		Schema: 1, ID: "testmod", Version: version, Protocol: 1,
		Zone: "A", Privilege: manifest.PrivilegeService, Session: manifest.SessionSystem,
		Platforms:    []manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Capabilities: caps,
	}
}

// localDir lays out an installable directory with a placeholder binary.
func localDir(t *testing.T, mf *manifest.Manifest, binName string) string {
	t.Helper()
	dir := t.TempDir()
	if binName != "" {
		if err := os.WriteFile(
			filepath.Join(dir, binName),
			[]byte("not really a binary"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	mb, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.manifest.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// installedVersion puts a version straight into the install tree, as a
// previous successful install would have.
func installedVersion(t *testing.T, m *Manager, mf *manifest.Manifest, withBinary bool) string {
	t.Helper()
	verDir := filepath.Join(m.Layout.ModulesDir, mf.ID, "versions", mf.Version)
	if err := os.MkdirAll(verDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if withBinary {
		if err := os.WriteFile(
			filepath.Join(verDir, binaryName(mf.ID)),
			[]byte("bin"),
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}
	mb, _ := json.Marshal(mf) //nolint:errcheck
	if err := os.WriteFile(filepath.Join(verDir, "module.manifest.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	return verDir
}

func marker(t *testing.T, m *Manager, id, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.Layout.ModulesDir, id, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("err = %v, want containing %q", err, contains)
	}
}

func TestInstallLocalErrors(t *testing.T) {
	m := gatedManager(t)
	ctx := context.Background()

	_, err := m.InstallLocal(ctx, t.TempDir())
	if err == nil {
		t.Fatal("install of a dir with no manifest succeeded")
	}

	_, err = m.InstallLocal(ctx, localDir(t, testManifest("1.0.0"), ""))
	wantErr(t, err, "no binary for testmod")

	m.Verifier = supervise.VerifierFunc(
		func(string, *manifest.Manifest) error { return errors.New("unsigned") },
	)
	_, err = m.InstallLocal(ctx, localDir(t, testManifest("1.0.0"), "module"))
	wantErr(t, err, "failed verification")
	if _, err := os.Stat(
		filepath.Join(m.Layout.StagingDir, "testmod", "1.0.0"),
	); !os.IsNotExist(
		err,
	) {
		t.Fatalf("a rejected stage must be removed: %v", err)
	}
}

// A promote whose gate fails, with an older version to fall back to whose
// own activation also fails, reports the original failure and leaves
// current pointing at the old version.
func TestPromoteFailsAndRollbackFailsToo(t *testing.T) {
	m := gatedManager(t)
	m.GateTimeout, m.GateStable = 0, 0 // defaults; the gate fails long before them
	installedVersion(t, m, testManifest("1.0.0", "platform.osinfo"), true)
	if err := writeFileString(
		filepath.Join(m.Layout.ModulesDir, "testmod", "current"),
		"1.0.0",
	); err != nil {
		t.Fatal(err)
	}

	cfgDir := localDir(t, testManifest("2.0.0", "platform.osinfo"), "testmod"+exeSuffix())
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := m.InstallLocal(context.Background(), cfgDir)
	wantErr(t, err, "failed health gate")
	wantErr(t, err, "requirements-unmet")
	if got := marker(t, m, "testmod", "current"); got != "1.0.0" {
		t.Fatalf("current = %q, want the old 1.0.0", got)
	}
	// The failed module is not left registered to be relaunched.
	for _, st := range m.Supervisor.Statuses() {
		if st.Version == "2.0.0" {
			t.Fatalf("failed version still supervised: %+v", st)
		}
	}
}

func TestPromoteFilesystemFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("module dir is a file", func(t *testing.T) {
		m := gatedManager(t)
		if err := os.WriteFile(
			filepath.Join(m.Layout.ModulesDir, "testmod"),
			[]byte("x"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := m.promote(ctx, testManifest("1.0.0"), t.TempDir()); err == nil {
			t.Fatal("promote into a blocked module dir succeeded")
		}
	})

	t.Run("stage missing", func(t *testing.T) {
		m := gatedManager(t)
		err := m.promote(ctx, testManifest("1.0.0"), filepath.Join(t.TempDir(), "gone"))
		wantErr(t, err, "promoting stage")
	})
}

func TestActivateFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("no binary", func(t *testing.T) {
		m := gatedManager(t)
		verDir := installedVersion(t, m, testManifest("1.0.0"), false)
		wantErr(t, m.activate(ctx, testManifest("1.0.0"), verDir), "no binary")
	})

	t.Run("supervisor refuses", func(t *testing.T) {
		m := gatedManager(t)
		m.Supervisor = &supervise.Supervisor{Log: m.Log} // no base context
		verDir := installedVersion(t, m, testManifest("1.0.0"), true)
		wantErr(t, m.activate(ctx, testManifest("1.0.0"), verDir), "SetBaseContext")
	})
}

func TestRollbackErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing retained", func(t *testing.T) {
		m := gatedManager(t)
		_, err := m.Rollback(ctx, "testmod")
		wantErr(t, err, "no previous version retained")
	})

	t.Run("previous has no manifest", func(t *testing.T) {
		m := gatedManager(t)
		if err := writeFileString(
			filepath.Join(m.Layout.ModulesDir, "testmod", "previous"),
			"1.0.0",
		); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Rollback(ctx, "testmod"); err == nil {
			t.Fatal("rollback to a version with no manifest succeeded")
		}
	})

	t.Run("previous fails its gate", func(t *testing.T) {
		m := gatedManager(t)
		installedVersion(t, m, testManifest("1.0.0", "platform.osinfo"), true)
		if err := writeFileString(
			filepath.Join(m.Layout.ModulesDir, "testmod", "previous"),
			"1.0.0",
		); err != nil {
			t.Fatal(err)
		}
		if err := writeFileString(
			filepath.Join(m.Layout.ModulesDir, "testmod", "current"),
			"2.0.0",
		); err != nil {
			t.Fatal(err)
		}
		_, err := m.Rollback(ctx, "testmod")
		wantErr(t, err, "requirements-unmet")
		if got := marker(t, m, "testmod", "previous"); got != "1.0.0" {
			t.Fatalf("a failed rollback rewrote previous to %q", got)
		}
	})
}

func TestHealthGateOutcomes(t *testing.T) {
	t.Run("vanished", func(t *testing.T) {
		m := gatedManager(t)
		wantErr(t, m.healthGate(context.Background(), "nobody"), "vanished")
	})

	// A module that cannot exec sits in starting/backoff: the gate keeps
	// waiting, then times out — or stops early when the caller gives up.
	notRunning := func(t *testing.T) *Manager {
		t.Helper()
		m := gatedManager(t)
		mf := testManifest("1.0.0") // no capability requirements: it is launched
		if err := m.Supervisor.Add(
			supervise.Spec{Manifest: mf, BinPath: filepath.Join(t.TempDir(), "absent")},
		); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("times out", func(t *testing.T) {
		m := notRunning(t)
		m.GateTimeout = 300 * time.Millisecond
		wantErr(t, m.healthGate(context.Background(), "testmod"), "timed out")
	})

	t.Run("caller cancels", func(t *testing.T) {
		m := notRunning(t)
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		if err := m.healthGate(ctx, "testmod"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the caller's deadline", err)
		}
	})
}

func TestStageFilesFailures(t *testing.T) {
	t.Run("staging dir blocked", func(t *testing.T) {
		m := gatedManager(t)
		if err := os.WriteFile(
			filepath.Join(m.Layout.StagingDir, "testmod"),
			[]byte("x"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := m.stageFiles(testManifest("1.0.0"), "unused", ""); err == nil {
			t.Fatal("staged under a file")
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		m := gatedManager(t)
		if _, err := m.stageFiles(
			testManifest("1.0.0"),
			filepath.Join(t.TempDir(), "absent"),
			"",
		); err == nil {
			t.Fatal("staged a missing binary")
		}
	})

	t.Run("config unreadable", func(t *testing.T) {
		m := gatedManager(t)
		bin := filepath.Join(t.TempDir(), "bin")
		if err := os.WriteFile(bin, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
		// A directory where config.json should be stats fine but cannot be copied.
		if _, err := m.stageFiles(testManifest("1.0.0"), bin, t.TempDir()); err == nil {
			t.Fatal("staged an unreadable config")
		}
	})
}

func TestPruneMissingDir(t *testing.T) {
	m := gatedManager(t)
	m.prune(filepath.Join(t.TempDir(), "absent"), "1", "0") // must not panic
}

func TestFindBinaryFallbackName(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, binaryName("x")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := findBinary(dir, "x")
	if err != nil || got != filepath.Join(dir, "module") {
		t.Fatalf(
			"findBinary = %q, %v (a directory named like the binary must be skipped)",
			got,
			err,
		)
	}
}

func TestBinaryNameMatchesPlatform(t *testing.T) {
	want := "m"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := binaryName("m"); got != want {
		t.Fatalf("binaryName = %q, want %q", got, want)
	}
}

func TestCopyFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := copyFile(filepath.Join(dir, "absent"), filepath.Join(dir, "dst"), 0o600); err == nil {
		t.Fatal("copied a missing file")
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, filepath.Join(dir, "no", "such", "dst"), 0o600); err == nil {
		t.Fatal("copied into a missing directory")
	}
	if err := copyFile(dir, filepath.Join(dir, "dst2"), 0o600); err == nil {
		t.Fatal("copied a directory as a file")
	}
}

func TestWriteFileStringErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "f")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileString(filepath.Join(blocker, "sub", "marker"), "v"); err == nil {
		t.Fatal("wrote under a regular file")
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(ro, 0o700) }) //nolint:errcheck
		if err := writeFileString(filepath.Join(ro, "marker"), "v"); err == nil {
			t.Fatal("wrote into a read-only directory")
		}
	}
}

// channelOrigin serves a signed channel bundle and one artifact, built
// from a manifest the test shapes.
type channelOrigin struct {
	srv      *httptest.Server
	rootPub  ed25519.PublicKey
	mu       sync.Mutex
	files    map[string][]byte
	status   map[string]int
	artifact []byte
}

func newOrigin(
	t *testing.T,
	artifact []byte,
	shape func(*manifest.ChannelManifest),
) *channelOrigin {
	t.Helper()
	o := &channelOrigin{files: map[string][]byte{}, status: map[string]int{}, artifact: artifact}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		o.mu.Lock()
		code, data := o.status[name], o.files[name]
		o.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		if name == "artifact.bin" {
			w.Write(o.artifact) //nolint:errcheck
			return
		}
		if data == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(o.srv.Close)

	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader) //nolint:errcheck
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader) //nolint:errcheck
	o.rootPub = rootPub
	signingKey, _ := json.Marshal(
		manifest.PublicKey{
			Schema:    1,
			KeyID:     "signing",
			PublicKey: base64.StdEncoding.EncodeToString(signPub),
		},
	) //nolint:errcheck
	endorse, _ := json.Marshal(
		manifest.Signature{
			Schema: 1,
			KeyID:  "root",
			Signature: base64.StdEncoding.EncodeToString( //nolint:errcheck
				ed25519.Sign(
					rootPriv,
					manifest.SigningMessage(manifest.EndorseContext, signingKey),
				),
			),
		},
	)

	ch := manifest.ChannelManifest{
		Schema: 1, Channel: "stable", Sequence: 5, GeneratedAt: "2026-08-10T00:00:00Z",
		Protocol: manifest.ProtocolWindow{Min: 1, Max: 1},
		Core:     manifest.ChannelCore{Version: "0.1.0", Artifacts: []manifest.ChannelArtifact{}},
		Modules: []manifest.ChannelModule{{
			ID: "testmod", Version: "1.0.0", Protocol: 1, Privilege: "service", Session: "system",
			Capabilities: []string{"platform.osinfo"},
			Artifacts: []manifest.ChannelArtifact{{
				OS: runtime.GOOS, Arch: runtime.GOARCH, URL: o.srv.URL + "/artifact.bin",
				Digest: sha256Digest(artifact), Size: int64(len(artifact)),
			}},
		}},
	}
	if shape != nil {
		shape(&ch)
	}
	mb, _ := json.Marshal(
		ch,
	) //nolint:errcheck
	msig, _ := json.Marshal(
		manifest.Signature{
			Schema: 1,
			KeyID:  "signing",
			Signature: base64.StdEncoding.EncodeToString( //nolint:errcheck
				ed25519.Sign(signPriv, manifest.SigningMessage(manifest.ManifestContext, mb))),
		},
	)
	o.files = map[string][]byte{
		"manifest.json": mb, "manifest.json.sig": msig,
		"signing.pub": signingKey, "signing.pub.sig": endorse,
	}
	return o
}

func (o *channelOrigin) fail(name string, code int) {
	o.mu.Lock()
	o.status[name] = code
	o.mu.Unlock()
}

func channelManager(t *testing.T, o *channelOrigin) *Manager {
	t.Helper()
	m := gatedManager(t)
	m.RootPub = o.rootPub
	m.ManifestURL = o.srv.URL + "/"
	return m
}

// memSeq is a SeqStore with injectable failures.
type memSeq struct {
	mu      sync.Mutex
	val     []byte
	found   bool
	getErr  error
	putErr  error
	putSeen []string
}

func (s *memSeq) Get(context.Context, string, string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val, s.found, s.getErr
}

func (s *memSeq) Put(_ context.Context, _, _ string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putSeen = append(s.putSeen, string(v))
	if s.putErr != nil {
		return s.putErr
	}
	s.val, s.found = v, true
	return nil
}

func TestInstallUnconfigured(t *testing.T) {
	_, err := gatedManager(t).Install(context.Background(), "testmod", "")
	wantErr(t, err, "no manifest source configured")
}

func TestInstallBundleFetchFailures(t *testing.T) {
	for _, name := range []string{"manifest.json", "manifest.json.sig", "signing.pub", "signing.pub.sig"} {
		t.Run(name, func(t *testing.T) {
			o := newOrigin(t, []byte("artifact"), nil)
			o.fail(name, http.StatusServiceUnavailable)
			_, err := channelManager(t, o).Install(context.Background(), "testmod", "")
			wantErr(t, err, name+": 503")
		})
	}

	t.Run("bad base URL", func(t *testing.T) {
		o := newOrigin(t, []byte("artifact"), nil)
		m := channelManager(t, o)
		m.ManifestURL = "http://bad host"
		if _, err := m.Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("fetched from an unparseable URL")
		}
	})

	t.Run("origin down", func(t *testing.T) {
		o := newOrigin(t, []byte("artifact"), nil)
		m := channelManager(t, o)
		o.srv.Close()
		if _, err := m.Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("fetched from a closed origin")
		}
	})
}

func TestInstallChannelContentRefusals(t *testing.T) {
	art := []byte("artifact")
	cases := map[string]struct {
		shape   func(*manifest.ChannelManifest)
		module  string
		version string
		want    string
	}{
		"expired": {
			shape:  func(c *manifest.ChannelManifest) { c.Expires = "2020-01-01T00:00:00Z" },
			module: "testmod", want: "expired",
		},
		"module absent": {module: "other", want: `module "other" not in channel`},
		"version mismatch": {
			module:  "testmod",
			version: "9.9.9",
			want:    "carries testmod@1.0.0, not 9.9.9",
		},
		"no artifact for host": {shape: func(c *manifest.ChannelManifest) {
			c.Modules[0].Artifacts[0].OS = "plan9"
		}, module: "testmod", want: "no artifact for"},
		"invalid module manifest": {
			shape:  func(c *manifest.ChannelManifest) { c.Modules[0].Protocol = 0 },
			module: "testmod", want: "protocol must be >= 1",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := newOrigin(t, art, c.shape)
			_, err := channelManager(t, o).Install(context.Background(), c.module, c.version)
			wantErr(t, err, c.want)
		})
	}
}

func TestInstallDownloadFailures(t *testing.T) {
	art := []byte("artifact")

	t.Run("artifact 404", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		o.fail("artifact.bin", http.StatusNotFound)
		_, err := channelManager(t, o).Install(context.Background(), "testmod", "")
		wantErr(t, err, "artifact fetch: 404")
	})

	t.Run("artifact URL unparseable", func(t *testing.T) {
		o := newOrigin(
			t,
			art,
			func(c *manifest.ChannelManifest) { c.Modules[0].Artifacts[0].URL = "http://bad host/a" },
		)
		if _, err := channelManager(t, o).Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("downloaded from an unparseable URL")
		}
	})

	t.Run("artifact host down", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		o := newOrigin(
			t,
			art,
			func(c *manifest.ChannelManifest) { c.Modules[0].Artifacts[0].URL = dead.URL + "/a" },
		)
		if _, err := channelManager(t, o).Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("downloaded from a closed host")
		}
	})

	t.Run("no staging dir", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		m := channelManager(t, o)
		if err := os.RemoveAll(m.Layout.StagingDir); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("downloaded with nowhere to put it")
		}
	})

	// The origin promises more bytes than it sends, then hangs up.
	t.Run("body cut short", func(t *testing.T) {
		cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(art)+100))
			w.Write(art) //nolint:errcheck
		}))
		t.Cleanup(cut.Close)
		o := newOrigin(t, art, func(c *manifest.ChannelManifest) {
			c.Modules[0].Artifacts[0].URL = cut.URL + "/a"
			c.Modules[0].Artifacts[0].Size = int64(len(art) + 100)
		})
		if _, err := channelManager(t, o).Install(context.Background(), "testmod", ""); err == nil {
			t.Fatal("accepted a truncated body")
		}
	})
}

func TestInstallStageAndPromoteFailures(t *testing.T) {
	art := []byte("artifact")

	t.Run("verification fails", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		m := channelManager(t, o)
		m.Verifier = supervise.VerifierFunc(
			func(string, *manifest.Manifest) error { return errors.New("unsigned") },
		)
		_, err := m.Install(context.Background(), "testmod", "1.0.0")
		wantErr(t, err, "failed verification")
	})

	t.Run("gate fails", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		m := channelManager(t, o)
		_, err := m.Install(context.Background(), "testmod", "")
		wantErr(t, err, "failed health gate")
	})
}

func TestChannelSequenceAntiRollback(t *testing.T) {
	art := []byte("artifact")
	ctx := context.Background()

	t.Run("older sequence refused", func(t *testing.T) {
		o := newOrigin(t, art, nil) // sequence 5
		m := channelManager(t, o)
		m.SeqStore = &memSeq{val: []byte("7\n"), found: true}
		_, err := m.fetchChannel(ctx)
		wantErr(t, err, "older than accepted 7")
	})

	t.Run("newer sequence recorded", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		m := channelManager(t, o)
		seq := &memSeq{val: []byte("3"), found: true}
		m.SeqStore = seq
		if _, err := m.fetchChannel(ctx); err != nil {
			t.Fatal(err)
		}
		if len(seq.putSeen) != 1 || seq.putSeen[0] != "5" {
			t.Fatalf("persisted %q, want [5]", seq.putSeen)
		}
		// Same sequence again: accepted, nothing to persist.
		if _, err := m.fetchChannel(ctx); err != nil {
			t.Fatal(err)
		}
		if len(seq.putSeen) != 1 {
			t.Fatalf("re-persisted an unchanged sequence: %q", seq.putSeen)
		}
	})

	// The high-water mark failing to persist is logged, not fatal: the
	// manifest itself is genuine and fresh.
	t.Run("persist fails", func(t *testing.T) {
		o := newOrigin(t, art, nil)
		m := channelManager(t, o)
		m.SeqStore = &memSeq{putErr: errors.New("disk full")}
		if _, err := m.fetchChannel(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unreadable mark counts as zero", func(t *testing.T) {
		for _, s := range []*memSeq{
			{getErr: errors.New("io")},
			{val: []byte("not a number"), found: true},
		} {
			o := newOrigin(t, art, nil)
			m := channelManager(t, o)
			m.SeqStore = s
			if _, err := m.fetchChannel(ctx); err != nil {
				t.Fatal(err)
			}
			if len(s.putSeen) != 1 || s.putSeen[0] != "5" {
				t.Fatalf("persisted %q, want [5]", s.putSeen)
			}
		}
	})
}

func TestDefaultClient(t *testing.T) {
	m := &Manager{}
	if c := m.client(); c == nil || c.Timeout != 5*time.Minute {
		t.Fatalf("default client = %+v", c)
	}
	own := &http.Client{}
	m.Client = own
	if m.client() != own {
		t.Fatal("configured client ignored")
	}
}

// A module that runs but never reports healthy must not pass the gate:
// liveness alone is not health.
func TestGateRefusesRunningButDegraded(t *testing.T) {
	m, sup, bin := newTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)
	m.GateTimeout = 1500 * time.Millisecond

	dir := makeInstallDir(t, bin, "1.0.0", 0)
	if err := os.WriteFile(
		filepath.Join(dir, "config.json"),
		[]byte(`{"health":"degraded"}`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	_, err := m.InstallLocal(ctx, dir)
	wantErr(t, err, "timed out waiting for healthy")
	if got := marker(t, m, "testmod", "current"); got != "" {
		t.Fatalf("a module that never got healthy was recorded current (%q)", got)
	}
}

// A per-user module installed while nobody is at the console is promoted
// on its verified binary alone: the gate cannot wait for a login.
func TestPerUserModulePromotedWithoutASession(t *testing.T) {
	m := gatedManager(t)
	m.Supervisor.Sessions = noConsole{}
	mf := testManifest("1.0.0")
	mf.Privilege = manifest.PrivilegeUser
	mf.Session = manifest.SessionPerUserConsole
	if _, err := m.InstallLocal(
		context.Background(),
		localDir(t, mf, binaryName(mf.ID)),
	); err != nil {
		t.Fatalf("install with no console session: %v", err)
	}
	if got := marker(t, m, mf.ID, "current"); got != "1.0.0" {
		t.Fatalf("current = %q", got)
	}
	if st, _ := m.statusOf(mf.ID); st.State != supervise.StateWaitingForSession {
		t.Fatalf("state = %s", st.State)
	}

	// per-user-all is refused at registration, so its install fails the gate.
	all := testManifest("2.0.0")
	all.Privilege = manifest.PrivilegeUser
	all.Session = manifest.SessionPerUserAll
	_, err := m.InstallLocal(context.Background(), localDir(t, all, binaryName(all.ID)))
	wantErr(t, err, "per-user-all")
}

type noConsole struct{}

func (noConsole) Current() session.Snapshot {
	return session.Snapshot{Changed: make(chan struct{})}
}
