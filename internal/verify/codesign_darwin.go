//go:build !dev

package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Refusals from the macOS verifier, each the fixed part of its message.
var (
	errNoTeamPin       = errors.New("pins no apple_team_id; refusing")
	errMalformedTeamID = errors.New("malformed apple_team_id")
	errCodesign        = errors.New("codesign rejected")
	errTeamMismatch    = errors.New("signed by a team the manifest does not pin")
	errNoTeam          = errors.New("signature carries no team identifier")
	errNoTeamLine      = errors.New("no TeamIdentifier in codesign output")
)

// newVerifier (release, macOS).
func newVerifier(_ *slog.Logger) supervise.Verifier {
	return supervise.VerifierFunc(codesignVerify)
}

// codesignVerify authenticates a module binary on macOS against the pinned
// absolute /usr/bin/codesign (SecStaticCode would need cgo; codesign uses
// the same trust store and is boring). The decisive check is a designated
// requirement that the signature chains to Apple AND carries the pinned
// Team ID:
//
//	anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"
//
// Without the `anchor apple generic` clause, a self-signed certificate with
// a forged OU field satisfies plain `--verify` — TeamIdentifier alone is
// attacker-chosen. The TeamIdentifier text check is kept as defense in
// depth and to reject ad-hoc/no-team binaries with a clear message.
func codesignVerify(path string, m *manifest.Manifest) error {
	if m.Signing == nil || m.Signing.AppleTeamID == "" {
		return fmt.Errorf("verify: manifest for %s %w", m.ID, errNoTeamPin)
	}
	if !teamIDRe.MatchString(m.Signing.AppleTeamID) {
		return fmt.Errorf(
			"verify: manifest for %s has %w %q",
			m.ID,
			errMalformedTeamID,
			m.Signing.AppleTeamID,
		)
	}

	req := fmt.Sprintf(
		`anchor apple generic and certificate leaf[subject.OU] = %q`,
		m.Signing.AppleTeamID,
	)
	// No caller context reaches a Verifier; codesign is local and bounded.
	// "-R=<text>" is an inline requirement; a separate "-R" argument is read as a
	// file path to a compiled requirement, which never exists.
	ctx := context.Background()
	// req is built from a teamIDRe-validated team id; no shell is involved.
	verify := exec.CommandContext( //nolint:gosec // G204: see above
		ctx, codesignPath, "--verify", "--strict=all", "-R="+req, path)
	var verr bytes.Buffer
	verify.Stderr = &verr
	if err := verify.Run(); err != nil {
		return fmt.Errorf("verify: %w %s (must chain to Apple with team %s): %s",
			errCodesign, path, m.Signing.AppleTeamID, strings.TrimSpace(verr.String()))
	}

	// Defense in depth: confirm the TeamIdentifier text too, and reject
	// ad-hoc/no-team binaries explicitly.
	// path is the module binary under verification, passed as one argument
	// to the pinned codesign; no shell is involved.
	display := exec.CommandContext( //nolint:gosec // G702: see above
		ctx, codesignPath, "-d", "-vv", path)
	var out bytes.Buffer
	display.Stderr = &out // codesign -d writes details to stderr.
	if err := display.Run(); err != nil {
		return fmt.Errorf("verify: codesign -d failed for %s: %w", path, err)
	}
	team, err := parseTeamIdentifier(out.String())
	if err != nil {
		return fmt.Errorf("verify: %s: %w", path, err)
	}
	if team != m.Signing.AppleTeamID {
		return fmt.Errorf(
			"verify: %s signed by team %q, manifest pins %q: %w",
			path,
			team,
			m.Signing.AppleTeamID,
			errTeamMismatch,
		)
	}
	return nil
}

// codesignPath is absolute so PATH cannot substitute another codesign. A
// var only so tests can stand in a scripted codesign: no test machine holds
// an Apple-chained identity to sign with. Nothing but a test writes it.
var codesignPath = "/usr/bin/codesign"

// teamIDRe guards the Team ID before it is interpolated into a codesign
// requirement string. Apple Team IDs are 10 uppercase alphanumerics.
var teamIDRe = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// parseTeamIdentifier extracts TeamIdentifier=XXXX from codesign -dvv
// output. "not set" (platform and ad-hoc binaries) is an error: there is
// no identity to pin.
func parseTeamIdentifier(out string) (string, error) {
	for line := range strings.Lines(out) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier="); ok {
			v = strings.TrimSpace(v)
			if v == "" || v == "not set" {
				return "", errNoTeam
			}
			return v, nil
		}
	}
	return "", errNoTeamLine
}
