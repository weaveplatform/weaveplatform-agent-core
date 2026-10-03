package winsvc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/transport"
)

// media lays out install media: the three binaries and a modules tree.
func media(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	for _, n := range Payload {
		if err := os.WriteFile(filepath.Join(src, exe(n)), []byte("bin:"+n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mod := filepath.Join(src, ModulesDirName, "weave-linux-presence")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(mod, "module.manifest.json"),
		[]byte("{}"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	return src
}

func channelKeyFile(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "channel.pub")
	if err := os.WriteFile(
		p,
		[]byte(base64.StdEncoding.EncodeToString(pub)+"\r\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	return p
}

type installEnv struct {
	in         Installer
	m          *fakeManager
	restricted []string
	log        *bytes.Buffer
}

func newInstall(t *testing.T) *installEnv {
	t.Helper()
	e := &installEnv{m: newFake(), log: &bytes.Buffer{}}
	root := t.TempDir()
	e.in = Installer{
		Manager:        e.m,
		Service:        Config{Name: "WeaveAgent", DisplayName: DefaultDisplayName},
		SourceDir:      media(t),
		InstallDir:     filepath.Join(root, "Program Files", "Weave"),
		StateDir:       filepath.Join(root, "ProgramData", "Weave"),
		ChannelKey:     channelKeyFile(t),
		ChannelKeyDest: filepath.Join(root, "ProgramData", "weave", "channel.pub"),
		Restrict: func(d string) error {
			e.restricted = append(e.restricted, d)
			return nil
		},
		Start: true,
		Waits: fastWaits,
		Log:   e.log,
	}
	return e
}

func TestInstallerFreshInstall(t *testing.T) {
	e := newInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	for _, n := range Payload {
		b, err := os.ReadFile(filepath.Join(e.in.InstallDir, exe(n)))
		if err != nil || string(b) != "bin:"+n {
			t.Fatalf("%s not installed: %q %v", n, b, err)
		}
	}
	if _, err := os.Stat(
		filepath.Join(e.in.InstallDir, "modules", "weave-linux-presence", "module.manifest.json"),
	); err != nil {
		t.Fatalf("modules tree not installed: %v", err)
	}
	key, err := os.ReadFile(e.in.ChannelKeyDest)
	if err != nil || strings.Contains(string(key), "\r") || !strings.HasSuffix(string(key), "\n") {
		t.Fatalf("channel key = %q, %v", key, err)
	}
	if !reflect.DeepEqual(e.restricted, []string{e.in.StateDir}) {
		t.Fatalf("restricted %v", e.restricted)
	}
	s := e.m.services["WeaveAgent"]
	wantArgs := []string{"--", "--modules-dir", filepath.Join(e.in.InstallDir, "modules")}
	if s.cfg.BinaryPath != filepath.Join(e.in.InstallDir, exe("weaveboot")) ||
		!reflect.DeepEqual(s.cfg.Args, wantArgs) {
		t.Fatalf("registered %s %q", s.cfg.BinaryPath, s.cfg.Args)
	}
	if st, _ := Query(e.m, "WeaveAgent"); st != Running {
		t.Fatalf("service %s after install --start", st)
	}
	if !strings.Contains(e.log.String(), "created") {
		t.Fatalf("log: %s", e.log.String())
	}
}

// Re-running the install over a running agent stops it to replace the
// binaries, drops modules the media no longer carries, updates the
// registration in place, and leaves it running even without --start.
func TestInstallerReinstallOverRunningService(t *testing.T) {
	e := newInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(e.in.InstallDir, "modules", "stale")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	e.m.log = nil
	e.in.Start = false
	e.in.Service.Env = []string{"WEAVE_LOG_LEVEL=debug"}
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.m.log, ","); got != "stop,configure WeaveAgent,start" {
		t.Fatalf("re-install sequence = %s", got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("a module dropped from the media survived the re-install")
	}
	if e.m.services["WeaveAgent"].cfg.Env[0] != "WEAVE_LOG_LEVEL=debug" {
		t.Fatal("environment not updated")
	}
	if !strings.Contains(e.log.String(), "updated in place") {
		t.Fatalf("log: %s", e.log.String())
	}
}

// Installing from the install directory itself copies nothing and so has
// no reason to stop a running service; without --start it leaves the
// service as it found it.
func TestInstallerInPlaceDoesNotStop(t *testing.T) {
	e := newInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	e.m.log = nil
	e.in.SourceDir = e.in.InstallDir
	e.in.Start = false
	e.in.ChannelKey = ""
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.m.log, ","); got != "configure WeaveAgent" {
		t.Fatalf("in-place re-install = %s", got)
	}
}

func TestInstallerRefusesBadChannelKey(t *testing.T) {
	for name, content := range map[string]string{
		"not base64": "!!!", "wrong size": base64.StdEncoding.EncodeToString([]byte("short")),
	} {
		e := newInstall(t)
		if err := os.WriteFile(e.in.ChannelKey, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := e.in.Run(); !errors.Is(err, ErrBadChannelKey) {
			t.Fatalf("%s: %v", name, err)
		}
		// Refused before anything was changed.
		if _, err := os.Stat(e.in.InstallDir); !os.IsNotExist(err) {
			t.Fatalf("%s: install dir created before the key was validated", name)
		}
	}
	e := newInstall(t)
	e.in.ChannelKey = filepath.Join(t.TempDir(), "missing")
	if err := e.in.Run(); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestInstallerFailures(t *testing.T) {
	e := newInstall(t)
	e.in.Service.Env = []string{"bad"}
	if err := e.in.Run(); err == nil {
		t.Fatal("invalid env accepted")
	}

	e = newInstall(t)
	e.m.openErr = errBoom
	if err := e.in.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("query failure = %v", err)
	}

	e = newInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	e.m.services["WeaveAgent"].stopErr = errBoom
	if err := e.in.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("stop failure = %v", err)
	}

	e = newInstall(t)
	if err := os.Remove(filepath.Join(e.in.SourceDir, exe("weavectl"))); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Run(); err == nil || !strings.Contains(err.Error(), "weavectl") {
		t.Fatalf("missing payload = %v", err)
	}

	e = newInstall(t)
	e.in.Restrict = func(string) error { return errBoom }
	if err := e.in.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("restrict failure = %v", err)
	}

	e = newInstall(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.in.StateDir = filepath.Join(blocker, "state")
	if err := e.in.Run(); err == nil {
		t.Fatal("unusable state dir accepted")
	}

	e = newInstall(t)
	e.in.ChannelKeyDest = filepath.Join(blocker, "channel.pub")
	if err := e.in.Run(); err == nil || !strings.Contains(err.Error(), "channel key") {
		t.Fatalf("unwritable key dest = %v", err)
	}

	e = newInstall(t)
	e.m.createErr = errBoom
	if err := e.in.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("create failure = %v", err)
	}
}

func TestInstallFilesErrors(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFiles(media(t), filepath.Join(blocker, "dst")); err == nil {
		t.Fatal("unusable install dir accepted")
	}
	// The modules path in the install dir is a file: clearing it works,
	// but a destination that cannot be written fails.
	dst := t.TempDir()
	src := media(t)
	if err := os.WriteFile(filepath.Join(dst, exe("weaveboot")), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dst, exe("weave-agent")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, exe("weave-agent"), "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallFiles(src, dst); err == nil {
		t.Fatal("rename over a non-empty directory succeeded")
	}
	// Payload with no modules tree still gets an (empty) modules dir —
	// the service's --modules-dir must name a directory that exists.
	src = media(t)
	if err := os.RemoveAll(filepath.Join(src, ModulesDirName)); err != nil {
		t.Fatal(err)
	}
	dst = t.TempDir()
	if err := InstallFiles(src, dst); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dst, ModulesDirName)); err != nil || !fi.IsDir() {
		t.Fatalf("modules dir missing: %v", err)
	}
}

// The installer writes the key where core will look for it. They are two
// copies of one path; this keeps them one.
func TestChannelKeyPathMatchesTransport(t *testing.T) {
	if DefaultChannelKeyPath() != transport.DefaultChannelKeyPath() {
		t.Fatalf(
			"installer writes %s, core reads %s",
			DefaultChannelKeyPath(),
			transport.DefaultChannelKeyPath(),
		)
	}
	t.Setenv("ProgramData", `D:\PD`)
	if DefaultChannelKeyPath() != transport.DefaultChannelKeyPath() {
		t.Fatalf(
			"installer writes %s, core reads %s",
			DefaultChannelKeyPath(),
			transport.DefaultChannelKeyPath(),
		)
	}
	t.Setenv("ProgramData", "")
	if DefaultChannelKeyPath() != transport.DefaultChannelKeyPath() {
		t.Fatalf(
			"installer writes %s, core reads %s",
			DefaultChannelKeyPath(),
			transport.DefaultChannelKeyPath(),
		)
	}
}

func TestSameDir(t *testing.T) {
	d := t.TempDir()
	if !sameDir(d, d+string(filepath.Separator)+".") {
		t.Fatal("same dir not recognised")
	}
	if sameDir(d, filepath.Join(d, "missing")) || sameDir(filepath.Join(d, "missing"), d) {
		t.Fatal("missing dir reported same")
	}
}
