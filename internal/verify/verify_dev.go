//go:build dev

package verify

import (
	"log/slog"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// newVerifier (dev builds only): accept unsigned binaries, loudly. This
// code path does not exist in release builds.
func newVerifier(log *slog.Logger) supervise.Verifier {
	return supervise.VerifierFunc(func(path string, m *manifest.Manifest) error {
		log.Warn("DEV BUILD: signature verification bypassed", "module", m.ID, "path", path)
		return nil
	})
}

// coreVerifier (dev builds only): accept any staged core, loudly.
func coreVerifier(log *slog.Logger) func(string) error {
	return func(path string) error {
		log.Warn("DEV BUILD: core signature verification bypassed", "path", path)
		return nil
	}
}
