package winsvc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/certtrust"
)

// Payload is the set of binaries an install places in the install
// directory. They travel together (spec.md §9); weaveboot finds core as
// "the binary beside me" on a fresh install, so they must be siblings.
var Payload = []string{"weaveboot", "weave-agent", "weavectl", "weavemanifest"}

// Names in the install directory beside the payload.
const (
	// ModulesDirName is the package-owned module tree, the counterpart of
	// /usr/lib/weave/modules.
	ModulesDirName = "modules"
	// CertFileName is the trusted code-signing certificate, kept so an
	// uninstall knows which certificate the install trusted.
	CertFileName = "weave-codesign.crt"
	// UninstallScript is core's uninstaller, copied from the media when it
	// is there.
	UninstallScript = "uninstall.ps1"
	// UninstallDirName holds one <id>.ps1 per module package installed after
	// core (agent-modules' packaging/modulezip): the record of which weave
	// packages are still on the machine.
	UninstallDirName = "uninstall.d"
)

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// Installer is the unattended install: lay down the payload, provision the
// channel key, lock down the state root, register the service, start it.
type Installer struct {
	Manager Manager
	// Service is the registration; BinaryPath and Args are derived from
	// InstallDir when empty.
	Service Config
	// SourceDir holds the payload (install media). Equal to InstallDir, or
	// empty, means the payload is already in place.
	SourceDir  string
	InstallDir string
	// StateDir is the state root to restrict to SYSTEM and Administrators.
	StateDir string
	// ChannelKey, when set, is a file holding the host's base64 Ed25519
	// public key, installed at ChannelKeyDest.
	ChannelKey     string
	ChannelKeyDest string
	// Restrict applies the state-root ACL; RestrictDir in production.
	Restrict func(dir string) error
	// TrustCert, when set, is the module code-signing certificate to trust
	// machine-wide, through Trust (certtrust.Trust at LocalMachine in
	// production). A copy is kept in InstallDir as CertFileName.
	TrustCert string
	Trust     func(*certtrust.Certificate) error
	Start     bool
	Waits     Waits
	Log       io.Writer
}

// Run performs the install. Every step is idempotent, so a failed install is
// fixed by fixing the cause and running the same command again.
func (in Installer) Run() error {
	cfg := in.Service
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = filepath.Join(in.InstallDir, exe("weaveboot"))
	}
	if cfg.Args == nil {
		// Mirrors the Linux unit's ExecStart: everything after -- goes to
		// core, and --modules-dir sends it to the package-owned tree beside
		// the binaries rather than the default under the state root.
		cfg.Args = []string{"--", "--modules-dir", filepath.Join(in.InstallDir, ModulesDirName)}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	var key []byte
	if in.ChannelKey != "" {
		k, err := readChannelKey(in.ChannelKey)
		if err != nil {
			return err
		}
		key = k
	}
	var cert *certtrust.Certificate
	if in.TrustCert != "" {
		c, err := certtrust.Load(in.TrustCert)
		if err != nil {
			return fmt.Errorf("winsvc: code-signing certificate: %w", err)
		}
		cert = c
	}

	// A running service holds its binaries open, and Windows refuses to
	// replace a mapped image, so a re-install that copies stops it first —
	// and starts it again afterwards even without Start, so that updating
	// the binaries never leaves a previously running agent stopped.
	restart := in.Start
	if needsCopy(in.SourceDir, in.InstallDir) {
		st, err := Query(in.Manager, cfg.Name)
		switch {
		case errors.Is(err, ErrNotInstalled):
		case err != nil:
			return fmt.Errorf("winsvc: querying %s: %w", cfg.Name, err)
		case st != Stopped:
			in.logf("stopping %s to replace its binaries", cfg.Name)
			if err := Stop(in.Manager, cfg.Name, in.Waits); err != nil {
				return err
			}
			restart = true
		}
	}
	in.logf("installing binaries into %s", in.InstallDir)
	if err := InstallFiles(in.SourceDir, in.InstallDir); err != nil {
		return err
	}
	if pkgs := packageIDs(in.InstallDir); len(pkgs) > 0 {
		in.logf("left module packages as they are: %s", strings.Join(pkgs, ", "))
	}
	if err := os.MkdirAll(in.StateDir, 0o700); err != nil {
		return fmt.Errorf("winsvc: creating state root %s: %w", in.StateDir, err)
	}
	in.logf("restricting %s to SYSTEM and Administrators", in.StateDir)
	if err := in.Restrict(in.StateDir); err != nil {
		return fmt.Errorf("winsvc: restricting %s: %w", in.StateDir, err)
	}
	// After the ACL: the key file then inherits it rather than being written
	// world-readable first and tightened after.
	if key != nil {
		in.logf("installing channel key at %s", in.ChannelKeyDest)
		if err := writeAtomic(in.ChannelKeyDest, key, 0o644); err != nil {
			return fmt.Errorf("winsvc: writing channel key: %w", err)
		}
	}
	// Before the service starts: core verifies every module against this
	// trust at its first discovery.
	if cert != nil {
		if err := in.trust(cert); err != nil {
			return err
		}
	}
	created, err := Install(in.Manager, cfg)
	if err != nil {
		return err
	}
	if created {
		in.logf("service %s created", cfg.Name)
	} else {
		in.logf("service %s updated in place", cfg.Name)
	}
	if !restart {
		return nil
	}
	in.logf("starting %s", cfg.Name)
	return Start(in.Manager, cfg.Name, in.Waits)
}

// trust keeps a copy of the certificate beside the binaries, then trusts it.
// The copy goes first: an uninstall finds the thumbprint there, so a trust
// it could not find would be one it could never remove.
func (in Installer) trust(c *certtrust.Certificate) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
	if err := writeAtomic(filepath.Join(in.InstallDir, CertFileName), pemBytes, 0o644); err != nil {
		return fmt.Errorf("winsvc: keeping the code-signing certificate: %w", err)
	}
	in.logf("trusting code-signing certificate %s (%s) in %s",
		c.Thumbprint, c.Subject, strings.Join(certtrust.Stores, " and "))
	if err := in.Trust(c); err != nil {
		return fmt.Errorf("winsvc: trusting the code-signing certificate: %w", err)
	}
	return nil
}

func (in Installer) logf(format string, a ...any) {
	if in.Log != nil {
		fmt.Fprintf(in.Log, format+"\n", a...)
	}
}

// ErrBadChannelKey is returned for a channel key file that is not one
// base64 Ed25519 public key.
var ErrBadChannelKey = errors.New("winsvc: not a base64 Ed25519 public key")

// readChannelKey validates the key the same way core will load it
// (transport.loadChannelKey): one base64 Ed25519 public key. Validating here
// turns a bad key into a failed install rather than a guest that boots and
// silently authenticates nobody.
func readChannelKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("winsvc: reading channel key: %w", err)
	}
	s := strings.TrimSpace(string(raw))
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: %s", ErrBadChannelKey, path)
	}
	return []byte(s + "\n"), nil
}

// InstallFiles copies the payload and, when present, the modules tree from
// src to dst. Each binary is copied to a temporary name and renamed over
// the old one, so an interrupted install leaves the previous binary whole.
func InstallFiles(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("winsvc: creating %s: %w", dst, err)
	}
	if !needsCopy(src, dst) {
		return mkdir(filepath.Join(dst, ModulesDirName))
	}
	for _, name := range Payload {
		if err := copyFile(
			filepath.Join(src, exe(name)),
			filepath.Join(dst, exe(name)),
		); err != nil {
			return err
		}
	}
	// Optional: a zip from before core shipped an uninstaller has none.
	if _, err := os.Stat(filepath.Join(src, UninstallScript)); err == nil {
		if err := copyFile(
			filepath.Join(src, UninstallScript),
			filepath.Join(dst, UninstallScript),
		); err != nil {
			return err
		}
	}
	srcModules := filepath.Join(src, ModulesDirName)
	dstModules := filepath.Join(dst, ModulesDirName)
	if fi, err := os.Stat(srcModules); err == nil && fi.IsDir() {
		if err := installModules(srcModules, dst); err != nil {
			return err
		}
	}
	return mkdir(dstModules)
}

// installModules brings the modules tree in dst in line with the media's,
// module by module, except for the modules a module package owns.
//
// Two installers write the tree. Core's media installs the modules it
// carries, and those it no longer carries must not survive a re-install, so
// each is replaced whole and any other is removed. agent-modules' module
// zips install one module each after core, and record it as
// uninstall.d\<id>.ps1; such a module belongs to its package, not to the
// media, so an upgrade of core leaves it exactly as it is — even when the
// media carries the same id, since the package is the later and more
// deliberate choice. Its own uninstaller removes it.
func installModules(srcModules, dst string) error {
	dstModules := filepath.Join(dst, ModulesDirName)
	owned := map[string]bool{}
	for _, id := range packageIDs(dst) {
		owned[id] = true
	}
	media := map[string]bool{}
	entries, err := os.ReadDir(srcModules)
	if err != nil {
		return fmt.Errorf("winsvc: reading %s: %w", srcModules, err)
	}
	for _, e := range entries {
		media[e.Name()] = true
		if owned[e.Name()] {
			continue
		}
		target := filepath.Join(dstModules, e.Name())
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("winsvc: clearing %s: %w", target, err)
		}
		if !e.IsDir() {
			if err := copyFile(filepath.Join(srcModules, e.Name()), target); err != nil {
				return err
			}
			continue
		}
		if err := copyTree(filepath.Join(srcModules, e.Name()), target); err != nil {
			return err
		}
	}
	existing, err := os.ReadDir(dstModules)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("winsvc: reading %s: %w", dstModules, err)
	}
	for _, e := range existing {
		if media[e.Name()] || owned[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dstModules, e.Name())); err != nil {
			return fmt.Errorf("winsvc: removing %s: %w", e.Name(), err)
		}
	}
	return nil
}

// packageIDs lists the module packages installed in dir after core: their
// ids, from uninstall.d\<id>.ps1.
func packageIDs(dir string) []string {
	entries, _ := os.ReadDir(filepath.Join(dir, UninstallDirName))
	var ids []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".ps1"); ok && !e.IsDir() {
			ids = append(ids, id)
		}
	}
	return ids
}

// mkdir creates dir and its parents with the install tree's mode.
func mkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("winsvc: creating %s: %w", dir, err)
	}
	return nil
}

func needsCopy(src, dst string) bool {
	return src != "" && !samePath(src, dst)
}

func samePath(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

func copyTree(src, dst string) error {
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("winsvc: reading %s: %w", p, err)
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return mkdir(target)
		}
		return copyFile(p, target)
	})
	if err != nil {
		return fmt.Errorf("winsvc: copying %s: %w", src, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("winsvc: reading %s: %w", src, err)
	}
	if err := writeAtomic(dst, data, 0o755); err != nil {
		return fmt.Errorf("winsvc: writing %s: %w", dst, err)
	}
	return nil
}

// writeAtomic writes via a temporary sibling and a rename.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := mkdir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return fmt.Errorf("winsvc: creating a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, mode)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		os.Remove(name)
		return fmt.Errorf("winsvc: installing %s: %w", path, werr)
	}
	return nil
}

// DefaultChannelKeyPath is where core looks for the channel key when it is
// given no --channel-pub. It must equal transport.DefaultChannelKeyPath — a
// test holds the two together — and is restated rather than imported so
// weaveboot does not link the whole transport stack for one path.
func DefaultChannelKeyPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return programData + `\weave\channel.pub`
	}
	return "/etc/weave/channel.pub"
}

// DefaultInstallDir is %ProgramFiles%\Weave.
func DefaultInstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Weave")
}
