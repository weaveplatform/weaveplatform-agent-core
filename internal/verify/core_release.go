//go:build !dev

package verify

import (
	"errors"
	"fmt"
	"log/slog"
)

// errCoreUnverified refuses a staged core while no core signing identity is
// provisioned.
var errCoreUnverified = errors.New("core signature verification not yet provisioned")

// coreVerifier (release, all OSes): fail closed. A core signing identity is
// not yet provisioned, so weaveboot refuses to promote a staged core
// rather than exec an unverified binary as the privileged root of the
// process tree. When core signing lands, this performs the same
// codesign/Authenticode check modules get, against core's pinned identity.
func coreVerifier(_ *slog.Logger) func(string) error {
	return func(path string) error {
		return fmt.Errorf("verify: %w; refusing to promote %s", errCoreUnverified, path)
	}
}
