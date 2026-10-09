//go:build !dev

package verify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/certtrust"
)

// buildNop builds the do-nothing test binary, unsigned.
func buildNop(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "weave-test-module.exe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/win/nop")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the test binary: %v\n%s", err, out)
	}
	return bin
}

// powershell runs a Windows PowerShell script and returns its output.
func powershell(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$ErrorActionPreference = 'Stop'; "+script).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// signWithThrowawayCert mints a self-signed code-signing certificate in
// CurrentUser\My (its private key never leaves the machine's key store),
// signs bin with it — SHA-256, untimestamped, since a test must not need a
// network TSA — and returns the certificate. The certificate and its key are
// deleted when the test ends.
func signWithThrowawayCert(t *testing.T, bin, cn string) *certtrust.Certificate {
	t.Helper()
	out := powershell(t, fmt.Sprintf(`
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=%s' `+
		`-CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 `+
		`-NotAfter (Get-Date).AddDays(1)
$s = Set-AuthenticodeSignature -FilePath '%s' -Certificate $c -HashAlgorithm SHA256
if (-not $s.SignerCertificate) { throw "not signed: $($s.StatusMessage)" }
[Convert]::ToBase64String($c.RawData)`, cn, bin))
	lines := strings.Split(out, "\n")
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("certificate from PowerShell: %v\n%s", err, out)
	}
	c, err := certtrust.Parse(der)
	if err != nil {
		t.Fatalf("the throwaway certificate is not one the installer would trust: %v", err)
	}
	t.Cleanup(func() {
		powershell(t, `Remove-Item -Force Cert:\CurrentUser\My\`+c.Thumbprint)
	})
	return c
}

// End to end, the way a guest trusts the weaveplatform certificate: a binary
// signed by a self-signed certificate is refused until the certificate is in
// Root and TrustedPublisher (what core's installer does, through the same
// certtrust code), accepted then under the pinned thumbprint and only that,
// refused when a byte of it changes, and refused again once the trust is
// removed (what the uninstaller does). It writes LocalMachine stores, so it
// needs an elevated token, which CI's Windows runner has; a CurrentUser\Root
// add would raise a modal confirmation dialog and hang instead.
func TestAuthenticodeAcceptsATrustedSelfSignedModule(t *testing.T) {
	bin := buildNop(t)
	cn := fmt.Sprintf("weave test signing %d", time.Now().UnixNano())
	cert := signWithThrowawayCert(t, bin, cn)
	m := testMod(cn, cert.Thumbprint)

	if err := authenticodeVerify(bin, m); err == nil ||
		!errors.Is(err, errWinVerifyTrust) {
		t.Fatalf("an untrusted self-signed chain: %v", err)
	}

	t.Cleanup(func() { _ = certtrust.Untrust(certtrust.LocalMachine, cert.Thumbprint) })
	if err := certtrust.Trust(certtrust.LocalMachine, cert); err != nil {
		// CI says it is elevated: a refusal there is a failure, not a reason
		// to skip.
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) && os.Getenv("WEAVE_TEST_WINDOWS_ELEVATED") != "1" {
			t.Skipf("not elevated: %v", err)
		}
		t.Fatal(err)
	}
	// CryptoAPI observes root-store changes asynchronously. This process has
	// already cached the untrusted chain above; give the temporary test trust
	// a bounded opportunity to propagate before exercising the pin and hash.
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := authenticodeVerify(bin, m)
		if err == nil {
			break
		}
		if !errors.Is(err, errWinVerifyTrust) || time.Now().After(deadline) {
			t.Fatalf("a trusted self-signed module refused after trust propagation: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := authenticodeVerify(
		bin,
		testMod(cn, strings.Repeat("AB", 20)),
	); !errors.Is(
		err,
		errThumbprintMismatch,
	) {
		t.Fatalf("another thumbprint pinned: %v", err)
	}

	tampered := filepath.Join(t.TempDir(), "tampered.exe")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	data[0x400] ^= 0xff // inside .text: covered by the Authenticode hash
	if err := os.WriteFile(tampered, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := authenticodeVerify(tampered, m); !errors.Is(err, errWinVerifyTrust) {
		t.Fatalf("a modified binary: %v", err)
	}

	if err := certtrust.Untrust(certtrust.LocalMachine, cert.Thumbprint); err != nil {
		t.Fatal(err)
	}
	if err := authenticodeVerify(bin, m); !errors.Is(err, errWinVerifyTrust) {
		t.Fatalf("accepted after the trust was removed: %v", err)
	}
}

// A binary the release workflow has just signed with the real weaveplatform
// certificate, on a machine whose installer trusted it: accepted under the
// pinned thumbprint, refused under another. No test machine holds the key,
// so this runs only in the release workflow (WEAVE_SIGNED_BINARY,
// WEAVE_SIGNED_THUMBPRINT); everywhere else it skips.
func TestAuthenticodeAcceptsARealSignature(t *testing.T) {
	bin, thumb := os.Getenv("WEAVE_SIGNED_BINARY"), os.Getenv("WEAVE_SIGNED_THUMBPRINT")
	if bin == "" || thumb == "" {
		t.Skip("no Authenticode-signed binary given (WEAVE_SIGNED_BINARY, WEAVE_SIGNED_THUMBPRINT)")
	}
	if err := authenticodeVerify(bin, testMod("weaveplatform code signing", thumb)); err != nil {
		t.Fatalf("%s refused under %s: %v", bin, thumb, err)
	}
	if err := authenticodeVerify(
		bin,
		testMod("weaveplatform code signing", strings.Repeat("00", 20)),
	); !errors.Is(
		err,
		errThumbprintMismatch,
	) {
		t.Fatalf("%s under another thumbprint: %v", bin, err)
	}
}
