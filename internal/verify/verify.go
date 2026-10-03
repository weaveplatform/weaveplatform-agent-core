// Package verify authenticates module binaries before exec. Modules are
// fetched after install, so Gatekeeper and SmartScreen protect nobody
// here: core checks signature and signing identity itself, every launch.
//
// The real implementations (codesign on macOS, WinVerifyTrust on Windows)
// land with the verify milestone. Until then release builds fail closed —
// every exec is refused — and dev builds (-tags dev) accept unsigned
// binaries so the harness can be developed and tested. The escape hatch
// physically does not exist in release builds.
package verify

import (
	"log/slog"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// New returns the platform module verifier for this build.
func New(log *slog.Logger) supervise.Verifier {
	return newVerifier(log)
}

// Core returns the staged-core verifier weaveboot uses before promoting a
// new core binary. Dev builds bypass; release builds fail closed until a
// core signing identity is provisioned (see coreVerifier per build tag).
func Core(log *slog.Logger) func(binPath string) error {
	return coreVerifier(log)
}
