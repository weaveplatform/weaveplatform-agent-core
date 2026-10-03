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
		}
	}
	p := platform.Paths()
	return Layout{
		StateDir:   p.StateDir,
		LogDir:     p.LogDir,
		RunDir:     p.RunDir,
		StagingDir: p.StagingDir,
		ModulesDir: filepath.Join(p.StateDir, "modules"),
	}
}

// Ensure creates every directory with owner-only permissions AND tightens
// any that already exist but are too permissive. MkdirAll does not chmod an
// existing directory, so an installer that created StateDir 0755 would
// silently break the "0700 is the gate" assumption the store and sockets
// rely on; the explicit chmod repairs that. RunDir holds sockets: 0700 is
// access control, not decoration.
func (l Layout) Ensure() error {
	for _, d := range []string{l.StateDir, l.LogDir, l.RunDir, l.StagingDir, l.ModulesDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("layout: create %s: %w", d, err)
		}
		if err := tightenDir(d); err != nil {
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
