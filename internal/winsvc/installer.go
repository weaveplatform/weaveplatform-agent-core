package winsvc

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Payload is the set of binaries an install places in the install
// directory. All three travel together (spec.md §9); weaveboot finds core as
// "the binary beside me" on a fresh install, so they must be siblings.
var Payload = []string{"weaveboot", "weave-agent", "weavectl"}

// ModulesDirName is the package-owned module tree under the install
// directory, the counterpart of /usr/lib/weave/modules.
const ModulesDirName = "modules"

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
	Start    bool
	Waits    Waits
	Log      io.Writer
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
	srcModules := filepath.Join(src, ModulesDirName)
	dstModules := filepath.Join(dst, ModulesDirName)
	if fi, err := os.Stat(srcModules); err == nil && fi.IsDir() {
		// Replaced wholesale: the tree is package-owned, like
		// /usr/lib/weave/modules, so a module dropped from the media must
		// not survive the re-install.
		if err := os.RemoveAll(dstModules); err != nil {
			return fmt.Errorf("winsvc: clearing %s: %w", dstModules, err)
		}
		if err := copyTree(srcModules, dstModules); err != nil {
			return err
		}
	}
	return mkdir(dstModules)
}

// mkdir creates dir and its parents with the install tree's mode.
func mkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("winsvc: creating %s: %w", dir, err)
	}
	return nil
}

func needsCopy(src, dst string) bool {
	return src != "" && !sameDir(src, dst)
}

func sameDir(a, b string) bool {
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
