//go:build !dev

package verify

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// newVerifier (release, Linux).
//
// Linux has no exec-time signature construct the way macOS has codesign and
// Windows has Authenticode. Its native mechanism is the package manager:
// modules ship as a signed .deb from a GPG-signed repository, and dpkg verifies
// provenance at install. That is where the signature is checked, and it is what
// every Linux agent in the field relies on.
//
// So core's job here is not to re-check a signature it has no key for. It is to
// confirm that what dpkg vouched for has not since become writable by anyone
// who is not root — because the moment it has, the install-time guarantee is
// worth nothing and core would be exec'ing whatever that party last wrote.
//
// The directory is checked as well as the file. A binary that is itself
// root-owned and 0755 can still be swapped wholesale by anyone able to write
// the directory containing it, so checking only the file would be a check in
// name. This is the same reasoning behind OpenSSH's StrictModes and sudo's
// refusal to read a group-writable sudoers.
//
// IMA appraisal would give a true exec-time signature check, and is the upgrade
// path if the threat model ever needs to survive a root-level compromise. It
// needs kernel config, a policy, and a key enrolled in the .ima keyring, none of
// which Debian enables by default.
func newVerifier(log *slog.Logger) supervise.Verifier {
	return supervise.VerifierFunc(func(path string, _ *manifest.Manifest) error {
		if err := rootOwnedAndUnwritable(path); err != nil {
			return err
		}
		// The directory holding it, for the swap-the-file case.
		if err := rootOwnedAndUnwritable(filepath.Dir(path)); err != nil {
			return err
		}
		if log != nil {
			log.Debug("module integrity rests on the package manager and root-only write access",
				"path", path)
		}
		return nil
	})
}

// Refusals from the Linux verifier, each the fixed part of its message.
var (
	errNoOwnership   = errors.New("cannot read ownership of")
	errNotRootOwned  = errors.New("dpkg's install-time guarantee does not cover it")
	errGroupWritable = errors.New("writable by group or other")
)

// rootOwnedAndUnwritable refuses anything a non-root party could have modified.
func rootOwnedAndUnwritable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("verify: %w %s", errNoOwnership, path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf(
			"verify: %s is owned by uid %d, not root — %w",
			path,
			stat.Uid,
			errNotRootOwned,
		)
	}
	// Group- or world-writable means someone other than root can replace the
	// contents after the package manager vouched for them.
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("verify: %s is mode %04o — %w", path, mode, errGroupWritable)
	}
	return nil
}
