//go:build !dev

package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the thumbprint Windows computes is SHA-1; this checks it
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	crypt "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// mintCert creates a self-signed certificate context with the given common
// name (empty for none) and returns it with its expected thumbprint.
func mintCert(t *testing.T, cn string) (*crypt.CERT_CONTEXT, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if cn != "" {
		tmpl.Subject = pkix.Name{CommonName: cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := crypt.CertCreateCertificateContext(
		crypt.X509_ASN_ENCODING|crypt.PKCS_7_ASN_ENCODING,
		der,
	)
	if err != nil || ctx == nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	t.Cleanup(func() { crypt.CertFreeCertificateContext(ctx) })
	sum := sha1.Sum(der) //nolint:gosec
	return ctx, strings.ToUpper(hex.EncodeToString(sum[:]))
}

func TestMatchPinPrefersTheThumbprint(t *testing.T) {
	cert, thumb := mintCert(t, "WeaveTest")
	if got, err := certThumbprint(cert); err != nil || got != thumb {
		t.Fatalf("certThumbprint = %q, %v; want %q", got, err, thumb)
	}
	// The thumbprint decides even when the subject would not match, and is
	// compared case-insensitively since tools print it either way.
	if err := matchPin("x.exe", cert, testMod("SomeoneElse", strings.ToLower(thumb))); err != nil {
		t.Fatalf("matching thumbprint refused: %v", err)
	}
	err := matchPin("x.exe", cert, testMod("WeaveTest", strings.Repeat("00", 20)))
	if err == nil || !strings.Contains(err.Error(), "thumbprint") {
		t.Fatalf("wrong thumbprint: %v", err)
	}
}

func TestMatchPinFallsBackToTheSubject(t *testing.T) {
	cert, _ := mintCert(t, "WeaveTest")
	if err := matchPin("x.exe", cert, testMod("WeaveTest", "")); err != nil {
		t.Fatalf("matching subject refused: %v", err)
	}
	if err := matchPin("x.exe", cert, testMod("WeaveTes", "")); err == nil {
		t.Fatal("a subject prefix was accepted")
	}
}

func TestMatchPinRefusesACertificateWithoutASubject(t *testing.T) {
	cert, _ := mintCert(t, "")
	err := matchPin("x.exe", cert, testMod("", ""))
	if err == nil || !strings.Contains(err.Error(), "no subject name") {
		t.Fatalf("subjectless certificate: %v", err)
	}
}

// Binaries that commonly carry an embedded Authenticode signature on a
// Windows host or runner. WinVerifyTrust here checks embedded signatures
// only, and revocation is cache-only, so whether any of these passes the
// chain check depends on the machine; the test skips rather than guess.
var embeddedSigned = []string{
	`C:\Program Files\PowerShell\7\pwsh.exe`,
	`C:\Program Files\Git\cmd\git.exe`,
	`C:\Windows\explorer.exe`,
	`C:\Windows\System32\ntoskrnl.exe`,
}

// A binary whose chain WinVerifyTrust accepts must still be refused when its
// leaf is not the pinned one: chain trust alone admits any publisher.
func TestAuthenticodeTrustedChainStillNeedsThePin(t *testing.T) {
	for _, path := range embeddedSigned {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		err := authenticodeVerify(path, testMod("Weave Not The Publisher", ""))
		if err == nil {
			t.Fatalf("%s accepted under a subject it is not signed by", path)
		}
		if strings.Contains(err.Error(), "WinVerifyTrust rejected") {
			continue
		}
		if !strings.Contains(err.Error(), "signed by") {
			t.Fatalf("%s: unexpected refusal: %v", path, err)
		}
		err = authenticodeVerify(path, testMod("Weave Not The Publisher", strings.Repeat("00", 20)))
		if err == nil || !strings.Contains(err.Error(), "thumbprint") {
			t.Fatalf("%s: wrong thumbprint pin: %v", path, err)
		}
		return
	}
	t.Skip("no binary on this machine passes WinVerifyTrust with cache-only revocation")
}

func TestWindowsNewVerifierIsAuthenticode(t *testing.T) {
	m := &manifest.Manifest{ID: "x"}
	if err := newVerifier(nil).Verify(`C:\nowhere.exe`, m); err == nil ||
		!strings.Contains(err.Error(), "authenticode_subject") {
		t.Fatalf("newVerifier = %v", err)
	}
}
