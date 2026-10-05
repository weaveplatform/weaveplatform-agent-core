package winsvc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/certtrust"
)

// shippedCert is the certificate the Windows zip carries.
const shippedCert = "../../packaging/windows/weave-codesign.crt"

// trustingInstall is a fresh install that trusts the shipped certificate,
// with the trust calls recorded in the fake SCM's log so their order against
// the service calls shows.
func trustingInstall(t *testing.T) (*installEnv, *[]string) {
	t.Helper()
	e := newInstall(t)
	if err := os.WriteFile(
		filepath.Join(e.in.SourceDir, UninstallScript),
		[]byte("# uninstall"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	var trusted []string
	e.in.TrustCert = shippedCert
	e.in.Trust = func(c *certtrust.Certificate) error {
		trusted = append(trusted, c.Thumbprint)
		e.m.record("trust")
		return nil
	}
	return e, &trusted
}

func TestInstallerTrustsTheCertificate(t *testing.T) {
	e, trusted := trustingInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	want, err := certtrust.Load(shippedCert)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*trusted, []string{want.Thumbprint}) {
		t.Fatalf("trusted %v", *trusted)
	}
	if got := strings.Join(
		e.m.log,
		",",
	); got != "trust,create WeaveAgent,configure WeaveAgent,start" {
		t.Fatalf("sequence %s: the trust must come before the service starts", got)
	}
	kept, err := certtrust.Load(filepath.Join(e.in.InstallDir, CertFileName))
	if err != nil || kept.Thumbprint != want.Thumbprint {
		t.Fatalf("kept copy: %v, %v", kept, err)
	}
	if _, err := os.Stat(filepath.Join(e.in.InstallDir, UninstallScript)); err != nil {
		t.Fatalf("uninstaller not installed: %v", err)
	}
	if !strings.Contains(e.log.String(), want.Thumbprint) {
		t.Fatalf("log: %s", e.log.String())
	}
}

func TestInstallerTrustFailures(t *testing.T) {
	e, _ := trustingInstall(t)
	bad := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(bad, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.in.TrustCert = bad
	if err := e.in.Run(); !errors.Is(err, certtrust.ErrNoCertificate) {
		t.Fatalf("bad certificate: %v", err)
	}
	if _, err := os.Stat(e.in.InstallDir); !os.IsNotExist(err) {
		t.Fatal("install dir created before the certificate was validated")
	}

	e, _ = trustingInstall(t)
	e.in.Trust = func(*certtrust.Certificate) error { return errBoom }
	if err := e.in.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("trust failure: %v", err)
	}
	if _, ok := e.m.services["WeaveAgent"]; ok {
		t.Fatal("service registered although the trust failed")
	}

	e, _ = trustingInstall(t)
	// A directory where the certificate copy goes.
	if err := os.MkdirAll(filepath.Join(e.in.InstallDir, CertFileName, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Run(); err == nil || !strings.Contains(err.Error(), "keeping") {
		t.Fatalf("unwritable copy: %v", err)
	}

	e, _ = trustingInstall(t)
	if err := os.MkdirAll(filepath.Join(e.in.InstallDir, UninstallScript, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Run(); err == nil {
		t.Fatal("unwritable uninstaller accepted")
	}
}

type uninstallEnv struct {
	u         Uninstaller
	m         *fakeManager
	untrusted []string
	log       *bytes.Buffer
}

// installed is a trusting install, run, with an Uninstaller pointed at it.
func installed(t *testing.T) *uninstallEnv {
	t.Helper()
	e, _ := trustingInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	u := &uninstallEnv{m: e.m, log: &bytes.Buffer{}}
	u.u = Uninstaller{
		Manager:    e.m,
		Name:       "WeaveAgent",
		Waits:      fastWaits,
		InstallDir: e.in.InstallDir,
		UntrustFn: func(th string) error {
			u.untrusted = append(u.untrusted, th)
			return nil
		},
		Log: u.log,
	}
	return u
}

// addPackage installs a module package the way agent-modules' modulezip
// does: its directory and its uninstall.d\<id>.ps1.
func addPackage(t *testing.T, dir, id string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dir, ModulesDirName, id, "module.manifest.json"))
	writeTestFile(t, filepath.Join(dir, UninstallDirName, id+".ps1"))
}

func writeTestFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallServiceOnly(t *testing.T) {
	u := installed(t)
	if err := u.u.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := Query(u.m, "WeaveAgent"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("service still there: %v", err)
	}
	if len(u.untrusted) != 0 {
		t.Fatal("untrusted without being asked")
	}
	if _, err := os.Stat(filepath.Join(u.u.InstallDir, exe("weave-agent"))); err != nil {
		t.Fatal("files removed without being asked")
	}
}

func TestUninstallEverything(t *testing.T) {
	u := installed(t)
	u.u.RemoveFiles, u.u.Untrust = true, true
	if err := u.u.Run(); err != nil {
		t.Fatal(err)
	}
	want, _ := certtrust.Load(shippedCert)
	if !reflect.DeepEqual(u.untrusted, []string{want.Thumbprint}) {
		t.Fatalf("untrusted %v", u.untrusted)
	}
	if _, err := os.Stat(u.u.InstallDir); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(u.u.InstallDir)
		t.Fatalf("install dir left: %v", entries)
	}
	// Again: nothing left to do, and nothing fails.
	u.untrusted = nil
	if err := u.u.Run(); err != nil {
		t.Fatal(err)
	}
	if len(u.untrusted) != 0 ||
		!strings.Contains(u.log.String(), "trusted no code-signing certificate") {
		t.Fatalf("second run untrusted %v; log %s", u.untrusted, u.log.String())
	}
}

// A module package installed after core keeps the certificate trusted, its
// directory and its uninstaller; core's own files and media modules go.
func TestUninstallKeepsWhatAModulePackageNeeds(t *testing.T) {
	u := installed(t)
	addPackage(t, u.u.InstallDir, "weave-windows-exec")
	u.u.RemoveFiles, u.u.Untrust = true, true
	self := filepath.Join(u.u.InstallDir, exe("weaveboot"))
	u.u.Self = self
	if err := u.u.Run(); err != nil {
		t.Fatal(err)
	}
	if len(u.untrusted) != 0 || !strings.Contains(u.log.String(), "weave-windows-exec remain") {
		t.Fatalf("untrusted %v with a package left; log %s", u.untrusted, u.log.String())
	}
	for _, p := range []string{
		self,
		filepath.Join(u.u.InstallDir, ModulesDirName, "weave-windows-exec", "module.manifest.json"),
		filepath.Join(u.u.InstallDir, UninstallDirName, "weave-windows-exec.ps1"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
	for _, p := range []string{
		filepath.Join(u.u.InstallDir, exe("weave-agent")),
		filepath.Join(u.u.InstallDir, CertFileName),
		filepath.Join(u.u.InstallDir, UninstallScript),
		filepath.Join(u.u.InstallDir, ModulesDirName, "weave-linux-presence"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left: %v", p, err)
		}
	}
	if !strings.Contains(u.log.String(), "running weaveboot") {
		t.Fatalf("log: %s", u.log.String())
	}
}

func TestUninstallFailures(t *testing.T) {
	u := installed(t)
	u.m.openErr = errBoom
	if err := u.u.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("service failure: %v", err)
	}

	u = installed(t)
	u.u.Untrust = true
	u.u.UntrustFn = func(string) error { return errBoom }
	if err := u.u.Run(); !errors.Is(err, errBoom) {
		t.Fatalf("untrust failure: %v", err)
	}

	u = installed(t)
	u.u.Untrust = true
	if err := os.WriteFile(
		filepath.Join(u.u.InstallDir, CertFileName),
		[]byte("x"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := u.u.Run(); !errors.Is(err, certtrust.ErrNoCertificate) {
		t.Fatalf("unreadable copy: %v", err)
	}

	// A payload name that is a non-empty directory cannot be removed.
	u = installed(t)
	u.u.RemoveFiles = true
	p := filepath.Join(u.u.InstallDir, "install.ps1")
	writeTestFile(t, filepath.Join(p, "x"))
	if err := u.u.Run(); err == nil || !strings.Contains(err.Error(), "install.ps1") {
		t.Fatalf("unremovable file: %v", err)
	}

	// A modules path that is a file cannot be read as a directory.
	u = installed(t)
	u.u.RemoveFiles = true
	modules := filepath.Join(u.u.InstallDir, ModulesDirName)
	if err := os.RemoveAll(modules); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, modules)
	if err := u.u.Run(); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("unreadable modules dir: %v", err)
	}
}

// A core upgrade from media with a modules tree converges the modules the
// media owns and leaves every module package exactly as it was, even one
// whose id the media also carries.
func TestReinstallKeepsModulePackages(t *testing.T) {
	e, _ := trustingInstall(t)
	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	addPackage(t, e.in.InstallDir, "weave-windows-exec")
	// A package that also ships in the media, at its own version.
	addPackage(t, e.in.InstallDir, "weave-linux-presence")
	pkgManifest := filepath.Join(e.in.InstallDir, ModulesDirName, "weave-linux-presence", "module.manifest.json")
	stale := filepath.Join(e.in.InstallDir, ModulesDirName, "dropped-from-media")
	writeTestFile(t, filepath.Join(stale, "module.manifest.json"))
	// A loose file in the media's tree is installed too.
	writeTestFile(t, filepath.Join(e.in.SourceDir, ModulesDirName, "README.txt"))

	if err := e.in.Run(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pkgManifest); string(b) != "x" {
		t.Fatalf("the package's module was replaced by the media's: %q", b)
	}
	if _, err := os.Stat(filepath.Join(e.in.InstallDir, ModulesDirName, "weave-windows-exec")); err != nil {
		t.Fatalf("a package's module was removed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("a module dropped from the media survived")
	}
	if _, err := os.Stat(filepath.Join(e.in.InstallDir, ModulesDirName, "README.txt")); err != nil {
		t.Fatalf("loose media file: %v", err)
	}
	if !strings.Contains(e.log.String(), "left module packages as they are") {
		t.Fatalf("log: %s", e.log.String())
	}
}
