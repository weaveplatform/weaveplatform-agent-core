package certtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The weaveplatform code-signing certificate the Windows zip ships, and the
// thumbprint the Windows module manifests pin.
const (
	shippedCert       = "../../packaging/windows/weave-codesign.crt"
	shippedThumbprint = "A6A3936288B9409ED7A3458CF81014A77AB59B51"
)

// mint makes a self-signed certificate; edit adjusts the template, and a
// non-nil parent key signs it as someone else.
func mint(t *testing.T, edit func(*x509.Certificate), parent *ecdsa.PrivateKey) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "weave test signing",
			Organization: []string{"weave test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	if edit != nil {
		edit(tmpl)
	}
	signer := key
	if parent != nil {
		signer = parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issuedBy makes a code-signing certificate issued by a different name.
func issuedBy(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "issuer"},
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The certificate the release ships is one the installer accepts, and is
// the one the module manifests pin.
func TestParseShippedCertificate(t *testing.T) {
	c, err := Load(shippedCert)
	if err != nil {
		t.Fatal(err)
	}
	if c.Thumbprint != shippedThumbprint {
		t.Fatalf("thumbprint %s, want %s", c.Thumbprint, shippedThumbprint)
	}
	if c.Subject != "CN=weaveplatform code signing,O=weaveplatform" {
		t.Fatalf("subject %q", c.Subject)
	}
}

func TestParseAcceptsDERAndPEM(t *testing.T) {
	der := mint(t, nil, nil)
	for name, raw := range map[string][]byte{
		"der": der,
		"pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	} {
		c, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Thumbprint != Thumbprint(der) || !ValidThumbprint(c.Thumbprint) {
			t.Fatalf("%s: thumbprint %s", name, c.Thumbprint)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := mint(t, nil, nil)
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"garbage":       {[]byte("not a certificate"), ErrNoCertificate},
		"wrong pem":     {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), ErrNoCertificate},
		"two pem":       {append(append([]byte{}, block...), block...), ErrNoCertificate},
		"not self-sign": {mint(t, nil, other), ErrNotSelfSigned},
		"other issuer":  {issuedBy(t, other), ErrNotSelfSigned},
		"ca": {mint(t, func(c *x509.Certificate) {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
		}, nil), ErrIsCA},
		"tls": {mint(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}, nil), ErrNotCodeSigning},
		"code and tls": {mint(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		}, nil), ErrNotCodeSigning},
		"no eku": {mint(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }, nil), ErrNotCodeSigning},
		"unknown eku": {mint(t, func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}, nil), ErrNotCodeSigning},
	} {
		if _, err := Parse(tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.crt")); err == nil {
		t.Fatal("missing file loaded")
	}
	p := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("bad file: %v", err)
	}
}

func TestValidThumbprintAndLocation(t *testing.T) {
	for s, want := range map[string]bool{
		shippedThumbprint: true, "a6a3936288b9409ed7a3458cf81014a77ab59b51": true,
		"A6A3": false, "": false, "Z6A3936288B9409ED7A3458CF81014A77AB59B51": false,
	} {
		if ValidThumbprint(s) != want {
			t.Errorf("ValidThumbprint(%q) = %v", s, !want)
		}
	}
	if LocalMachine.String() != "LocalMachine" || CurrentUser.String() != "CurrentUser" {
		t.Fatal("location names")
	}
}
