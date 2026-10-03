//go:build !dev

package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// These are Windows-host handoff tests for the Authenticode verifier. They
// need a Windows machine with PowerShell to mint a self-signed cert and
// sign a binary. Run on Windows: `go test ./internal/verify/`.
//
// What they must prove:
//   1. an unsigned binary is refused;
//   2. a binary signed by a self-signed cert (untrusted chain) is refused —
//      this is the Authenticode analogue of the macOS "anchor apple" gap;
//   3. a thumbprint mismatch is refused when the manifest pins a thumbprint.
//
// Setup sketch (PowerShell), for the LLM running this on Windows:
//   $c = New-SelfSignedCertificate -Type CodeSigning -Subject "CN=WeaveTest" `
//        -CertStoreLocation Cert:\CurrentUser\My
//   Set-AuthenticodeSignature -FilePath test.exe -Certificate $c
//   # $c.Thumbprint is the SHA-1 thumbprint to pin.

func testMod(subject, thumbprint string) *manifest.Manifest {
	m := &manifest.Manifest{
		Schema:    1,
		ID:        "testmod",
		Version:   "0.0.1",
		Protocol:  1,
		Zone:      "A",
		Privilege: "service",
		Session:   "system",
		Platforms: []manifest.Platform{{OS: "windows", Arch: "amd64"}},
		Signing: &manifest.Signing{
			AuthenticodeSubject:    subject,
			AuthenticodeThumbprint: thumbprint,
		},
	}
	return m
}

func TestAuthenticodeRefusesUnsigned(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "unsigned.exe")
	// A freshly built Go binary is unsigned.
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/win/nop")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf(
			"could not build test binary (provide testdata/win/nop on the Windows host): %v\n%s",
			err,
			out,
		)
	}
	if err := authenticodeVerify(bin, testMod("WeaveTest", "")); err == nil {
		t.Fatal("unsigned binary accepted")
	}
}

func TestAuthenticodeRefusesNoPin(t *testing.T) {
	if _, err := os.Stat(`C:\Windows\System32\notepad.exe`); err != nil {
		t.Skip("notepad.exe not present")
	}
	// A manifest with neither subject nor thumbprint must be refused before
	// any verification runs.
	m := &manifest.Manifest{Schema: 1, ID: "x", Signing: &manifest.Signing{}}
	if err := authenticodeVerify(`C:\Windows\System32\notepad.exe`, m); err == nil {
		t.Fatal("manifest with no pinned identity accepted")
	}
}
