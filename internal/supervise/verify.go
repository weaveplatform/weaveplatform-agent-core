package supervise

import (
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// Verifier authenticates a module binary before exec. Modules are fetched
// after install, so Gatekeeper is not protecting anyone: core verifies
// signature and signing identity itself, every launch.
//
// The production implementations (codesign on macOS, WinVerifyTrust on
// Windows) land in internal/verify; this interface is the seam.
type Verifier interface {
	// Verify returns nil only when path is an acceptable binary for m.
	Verify(path string, m *manifest.Manifest) error
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(path string, m *manifest.Manifest) error

// Verify implements Verifier.
func (f VerifierFunc) Verify(path string, m *manifest.Manifest) error { return f(path, m) }
