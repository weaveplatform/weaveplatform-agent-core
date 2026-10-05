package winsvc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/certtrust"
)

// Uninstaller removes what Installer did: the service always, and on
// request the installed files and the machine's trust in the code-signing
// certificate. The state root (%ProgramData%\Weave: the device identity, its
// store and policy) is never touched; deleting it is the purge, and it is
// the operator's call.
type Uninstaller struct {
	Manager    Manager
	Name       string
	Waits      Waits
	InstallDir string
	// RemoveFiles removes core's payload, its uninstaller and certificate
	// copy, and the modules core's own media installed. Module packages
	// installed after core (each with an uninstall.d\<id>.ps1) keep their
	// directories and uninstallers.
	RemoveFiles bool
	// Untrust takes the certificate the install trusted (its copy in
	// InstallDir) out of the machine's stores, through UntrustFn
	// (certtrust.Untrust at LocalMachine in production) — unless a module
	// package remains, which was installed on the strength of that trust.
	Untrust   bool
	UntrustFn func(thumbprint string) error
	// Self is the running weaveboot. Windows will not delete a running
	// image, so it is left and reported; core's uninstall.ps1 runs a copy
	// from a temporary directory so that nothing is left.
	Self string
	Log  io.Writer
}

// Run uninstalls. Like the install, every step is idempotent.
func (u Uninstaller) Run() error {
	if err := Uninstall(u.Manager, u.Name, u.Waits); err != nil {
		return err
	}
	u.logf("service %s removed", u.Name)
	if u.Untrust {
		if err := u.untrust(); err != nil {
			return err
		}
	}
	if u.RemoveFiles {
		return u.removeFiles()
	}
	return nil
}

func (u Uninstaller) untrust() error {
	certPath := filepath.Join(u.InstallDir, CertFileName)
	c, err := certtrust.Load(certPath)
	if errors.Is(err, fs.ErrNotExist) {
		u.logf("no %s: this install trusted no code-signing certificate", certPath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("winsvc: %w", err)
	}
	if pkgs := packageIDs(u.InstallDir); len(pkgs) > 0 {
		u.logf("keeping code-signing certificate %s trusted: module packages %s remain",
			c.Thumbprint, strings.Join(pkgs, ", "))
		return nil
	}
	u.logf(
		"removing code-signing certificate %s from %s",
		c.Thumbprint,
		strings.Join(certtrust.Stores, " and "),
	)
	if err := u.UntrustFn(c.Thumbprint); err != nil {
		return fmt.Errorf("winsvc: removing the code-signing certificate: %w", err)
	}
	return nil
}

func (u Uninstaller) removeFiles() error {
	names := make([]string, 0, len(Payload)+3)
	for _, n := range Payload {
		names = append(names, exe(n))
	}
	names = append(names, UninstallScript, "install.ps1", CertFileName)
	for _, n := range names {
		p := filepath.Join(u.InstallDir, n)
		if u.Self != "" && samePath(p, u.Self) {
			u.logf("leaving %s: it is the running weaveboot; delete it once this exits", p)
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("winsvc: removing %s: %w", p, err)
		}
	}

	// The modules core's media installed go; a module package's directory
	// stays with the uninstaller that owns it.
	keep := map[string]bool{}
	for _, id := range packageIDs(u.InstallDir) {
		keep[id] = true
	}
	modules := filepath.Join(u.InstallDir, ModulesDirName)
	entries, err := os.ReadDir(modules)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("winsvc: reading %s: %w", modules, err)
	}
	for _, e := range entries {
		if keep[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(modules, e.Name())); err != nil {
			return fmt.Errorf("winsvc: removing module %s: %w", e.Name(), err)
		}
	}
	if len(keep) > 0 {
		u.logf("left module packages in place: run their uninstallers in %s",
			filepath.Join(u.InstallDir, UninstallDirName))
	}
	// Each only if empty: what remains belongs to a module package, or to
	// the running weaveboot.
	for _, d := range []string{modules, filepath.Join(u.InstallDir, UninstallDirName), u.InstallDir} {
		_ = os.Remove(d)
	}
	u.logf("files removed from %s", u.InstallDir)
	return nil
}

func (u Uninstaller) logf(format string, a ...any) {
	if u.Log != nil {
		fmt.Fprintf(u.Log, format+"\n", a...)
	}
}
