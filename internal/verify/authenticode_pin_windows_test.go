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
	"errors"
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

// Each way a manifest can pin the signer: thumbprint only, subject only,
// both (both must hold), and neither (refused before any verification).
func TestMatchPin(t *testing.T) {
	cert, thumb := mintCert(t, "WeaveTest")
	if got, err := certThumbprint(cert); err != nil || got != thumb {
		t.Fatalf("certThumbprint = %q, %v; want %q", got, err, thumb)
	}
	other := strings.Repeat("00", 20)
	for name, tc := range map[string]struct {
		subject, thumbprint string
		want                error
	}{
		// Compared case-insensitively: tools print thumbprints either way.
		"thumbprint only":        {"", strings.ToLower(thumb), nil},
		"thumbprint only, wrong": {"", other, errThumbprintMismatch},
		"subject only":           {"WeaveTest", "", nil},
		"subject only, a prefix": {"WeaveTes", "", errSubjectMismatch},
		"both":                   {"WeaveTest", thumb, nil},
		"both, subject wrong":    {"SomeoneElse", thumb, errSubjectMismatch},
		"both, thumbprint wrong": {"WeaveTest", other, errThumbprintMismatch},
		"both wrong":             {"SomeoneElse", other, errThumbprintMismatch},
	} {
		err := matchPin("x.exe", cert, testMod(tc.subject, tc.thumbprint))
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	for name, s := range map[string]*manifest.Signing{"no signing": nil, "empty signing": {}} {
		m := testMod("", "")
		m.Signing = s
		if err := authenticodeVerify(
			`C:\Windows\System32\notepad.exe`,
			m,
		); !errors.Is(
			err,
			errNoPin,
		) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMatchPinRefusesACertificateWithoutASubject(t *testing.T) {
	cert, _ := mintCert(t, "")
	err := matchPin("x.exe", cert, testMod("Someone", ""))
	if !errors.Is(err, errNoSubjectName) {
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
	if err := newVerifier(nil).Verify(`C:\nowhere.exe`, m); !errors.Is(err, errNoPin) {
		t.Fatalf("newVerifier = %v", err)
	}
}
