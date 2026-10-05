// Package layout resolves where core keeps things. The defaults are the
// platform filesystem contract from internal/platform; WEAVE_STATE_DIR (or the
// --state-dir flag) redirects everything under one directory for
// development and tests.
package layout

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
)

// EnvStateDir redirects the entire layout under one root when set.
const EnvStateDir = "WEAVE_STATE_DIR"

// Layout is the resolved set of directories core uses.
type Layout struct {
	// StateDir: durable state — store, installed modules, cached manifests.
	StateDir string
	// LogDir: rotating logs.
	LogDir string
	// RunDir: sockets and pidfiles.
	RunDir string
	// StagingDir: fetched-but-not-promoted artifacts.
	StagingDir string
	// ModulesDir: installed module versions.
	ModulesDir string
	// ExecDir: root-owned copies of module binaries that run as another
	// identity (a service account, a console user), which cannot reach the
	// 0700 tree the originals are installed in — and on Windows of every
	// module, so a running one never locks its install. It is always under StateDir,
	// never RunDir: RunDir is /run on Linux, which distributions mount
	// noexec, and the state volume is where the system already executes
	// core itself from (StateDir/core).
	ExecDir string
}

// Relocated reports whether Resolve(override) moves the layout under one root
// rather than returning the platform contract.
func Relocated(override string) bool {
	return override != "" || os.Getenv(EnvStateDir) != ""
}

// Resolve returns the layout, honouring override (highest precedence) then
// EnvStateDir, then the platform contract.
func Resolve(override string) Layout {
	if override == "" {
		override = os.Getenv(EnvStateDir)
	}
	if override != "" {
		return Layout{
			StateDir:   override,
			LogDir:     filepath.Join(override, "logs"),
			RunDir:     filepath.Join(override, "run"),
			StagingDir: filepath.Join(override, "staging"),
			ModulesDir: filepath.Join(override, "modules"),
			ExecDir:    filepath.Join(override, "exec"),
		}
	}
	p := platform.Paths()
	return Layout{
		StateDir:   p.StateDir,
		LogDir:     p.LogDir,
		RunDir:     p.RunDir,
		StagingDir: p.StagingDir,
		ModulesDir: filepath.Join(p.StateDir, "modules"),
		ExecDir:    filepath.Join(p.StateDir, "exec"),
	}
}

// Access modes for the layout's directories (unix; ACLs govern Windows).
const (
	// modePrivate: owner only. Everything that holds data — logs, staged
	// artifacts, installed modules, core's versions — is this.
	modePrivate os.FileMode = 0o700
	// modeTraverse: search-only for others. A module dropped to another
	// identity must walk through StateDir to its staged binary and through
	// RunDir to its socket dir, and nothing more: it cannot list either, and
	// what it reaches below is 0700 or root-owned read-only. The store and
	// key directly under StateDir are 0600 files, so traversal grants no
	// access to them.
	modeTraverse os.FileMode = 0o711
)

// dirMode is one directory Ensure manages and the mode it holds it at.
type dirMode struct {
	path string
	mode os.FileMode
}

// dirs is every directory Ensure manages, parents first.
func (l Layout) dirs() []dirMode {
	return []dirMode{
		{l.StateDir, modeTraverse},
		{l.LogDir, modePrivate},
		{l.RunDir, modeTraverse},
		{l.StagingDir, modePrivate},
		{l.ModulesDir, modePrivate},
		{l.ExecDir, modeTraverse},
	}
}

// Ensure creates every directory and sets its mode, including on one that
// already exists: MkdirAll does not chmod an existing directory, so an
// installer that created StateDir 0755 would silently leave it listable,
// and a 0700 left by an older core would lock out the identities modules
// drop to. Each directory is held at exactly its mode — private, or
// search-only for others where a dropped module must pass through.
func (l Layout) Ensure() error {
	for _, d := range l.dirs() {
		if err := os.MkdirAll(d.path, modePrivate); err != nil {
			return fmt.Errorf("layout: create %s: %w", d.path, err)
		}
		if err := setDirMode(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
}

// ControlSocket is the control service endpoint: a socket path on unix, a
// fixed pipe name on Windows.
func (l Layout) ControlSocket() string {
	if isWindows {
		return `\\.\pipe\weave-control`
	}
	return filepath.Join(l.RunDir, "control.sock")
}

// PolicyFile is where core reads the device's policy set from.
func (l Layout) PolicyFile() string {
	return filepath.Join(l.StateDir, "policy.json")
}

// ModuleRunDir is the per-module socket directory.
func (l Layout) ModuleRunDir(id string) string {
	return filepath.Join(l.RunDir, "modules", id)
}

// ModuleExecDir is where one module's staged binary lives.
func (l Layout) ModuleExecDir(id string) string {
	return filepath.Join(l.ExecDir, id)
}
