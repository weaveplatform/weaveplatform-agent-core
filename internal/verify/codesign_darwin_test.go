//go:build !dev

package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

func testManifest(team string) *manifest.Manifest {
	m := &manifest.Manifest{
		Schema: 1, ID: "testmod", Version: "0.0.1", Protocol: 1,
		Zone: "A", Privilege: "service", Session: "system",
		Platforms: []manifest.Platform{{OS: "darwin", Arch: "arm64"}},
	}
	if team != "" {
		m.Signing = &manifest.Signing{AppleTeamID: team}
	}
	return m
}

func TestParseTeamIdentifier(t *testing.T) {
	out := "Executable=/x\nIdentifier=com.example.tool\nTeamIdentifier=ABCDE12345\nSealed Resources=none\n"
	team, err := parseTeamIdentifier(out)
	if err != nil || team != "ABCDE12345" {
		t.Fatalf("got %q, %v", team, err)
	}
	if _, err := parseTeamIdentifier("TeamIdentifier=not set\n"); err == nil {
		t.Error("'not set' accepted")
	}
	if _, err := parseTeamIdentifier("Identifier=x\n"); err == nil {
		t.Error("missing TeamIdentifier accepted")
	}
}

func TestCodesignRefusesUnsigned(t *testing.T) {
	// A freshly built Go binary has no signature (linker ad-hoc signing
	// on arm64 yields no team either way).
	bin := filepath.Join(t.TempDir(), "unsigned")
	src := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644) //nolint:errcheck
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	err := codesignVerify(bin, testManifest("ABCDE12345"))
	if err == nil {
		t.Fatal("unsigned/ad-hoc binary accepted")
	}
}

func TestCodesignRefusesNoPin(t *testing.T) {
	if err := codesignVerify("/bin/ls", testManifest("")); err == nil ||
		!strings.Contains(err.Error(), "pins no apple_team_id") {
		t.Fatalf("manifest without team pin not refused correctly: %v", err)
	}
}

func TestCodesignRefusesPlatformBinary(t *testing.T) {
	// /bin/ls verifies but its TeamIdentifier is "not set" — no identity
	// to pin, must refuse.
	err := codesignVerify("/bin/ls", testManifest("ABCDE12345"))
	if err == nil {
		t.Fatal("platform binary with no team identifier accepted")
	}
}

// The requirement must reach the real codesign as an inline requirement. A
// binary that does not match the team is then refused for failing the
// requirement, never because codesign could not read it.
func TestCodesignVerifyEvaluatesTheRequirement(t *testing.T) {
	if _, err := os.Stat(codesignPath); err != nil {
		t.Skip("no codesign on this host")
	}
	err := codesignVerify("/usr/bin/true", testManifest("ABCDE12345"))
	if err == nil {
		t.Fatal("an Apple platform binary satisfied a third-party team requirement")
	}
	msg := err.Error()
	if strings.Contains(msg, "invalid requirement") || strings.Contains(msg, "No such file") {
		t.Fatalf("codesign could not read the requirement: %v", err)
	}
	if !strings.Contains(msg, "failed to satisfy") {
		t.Fatalf("want a requirement failure, got: %v", err)
	}
}

// A binary signed by a real Developer ID identity: core accepts it for the
// team that signed it and refuses it for any other. No test machine holds the
// identity, so this runs only where the release workflow has just signed one
// (WEAVE_SIGNED_BINARY, WEAVE_SIGNED_TEAM); everywhere else it skips.
func TestCodesignAcceptsARealSignature(t *testing.T) {
	bin, team := os.Getenv("WEAVE_SIGNED_BINARY"), os.Getenv("WEAVE_SIGNED_TEAM")
	if bin == "" || team == "" {
		t.Skip("no Developer ID signed binary given (WEAVE_SIGNED_BINARY, WEAVE_SIGNED_TEAM)")
	}
	if err := codesignVerify(bin, testManifest(team)); err != nil {
		t.Fatalf("a binary signed by team %s refused: %v", team, err)
	}
	other := "ZZZZZZZZZZ"
	if team == other {
		other = "YYYYYYYYYY"
	}
	err := codesignVerify(bin, testManifest(other))
	if err == nil || !strings.Contains(err.Error(), "failed to satisfy") {
		t.Fatalf("a binary signed by team %s accepted for team %s: %v", team, other, err)
	}
}
