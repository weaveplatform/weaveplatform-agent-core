// Package certtrust puts a self-signed code-signing certificate into the
// Windows machine's trust, and takes it out again: the install-time,
// out-of-band step that lets WinVerifyTrust accept modules signed with it.
//
// It is the Windows counterpart of baking a key into an image. The
// certificate arrives on the install media beside the binaries (the release
// zip, itself covered by the cosign-signed checksum file), and nothing on the
// channel ever reaches this package.
//
// A certificate in LocalMachine\Root is trusted for whatever its own
// extensions allow, machine-wide. So Parse refuses anything but the narrow
// shape a module signing certificate needs — self-signed, not a CA, code
// signing and nothing else — which keeps a tampered or mistaken certificate
// on the media from becoming a root that issues TLS certificates or anything
// else.
package certtrust

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the thumbprint Windows keys certificates by is SHA-1
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Stores are the LocalMachine (or CurrentUser) system stores a trusted
// signing certificate goes into. Root makes the chain WinVerifyTrust builds
// end in a trusted anchor; TrustedPublisher is what Windows consults where
// trusting the publisher is a separate decision (PowerShell's AllSigned,
// software restriction and driver policies).
var Stores = []string{"Root", "TrustedPublisher"}

// Location is the system store location a certificate is trusted in.
type Location int

// Locations. The installer uses LocalMachine: core runs as LocalSystem, and
// a CurrentUser store would be that of whoever ran the install.
const (
	LocalMachine Location = iota
	CurrentUser
)

func (l Location) String() string {
	if l == CurrentUser {
		return "CurrentUser"
	}
	return "LocalMachine"
}

// Why a certificate is refused.
var (
	ErrNoCertificate  = errors.New("certtrust: not one PEM or DER certificate")
	ErrNotSelfSigned  = errors.New("certtrust: not self-signed")
	ErrIsCA           = errors.New("certtrust: a CA certificate, not a signing certificate")
	ErrNotCodeSigning = errors.New("certtrust: not a code-signing-only certificate")
	ErrUnsupported    = errors.New("certtrust: system certificate stores are Windows-only")
)

// Certificate is a parsed, accepted signing certificate.
type Certificate struct {
	DER []byte
	// Thumbprint is the upper-case hex SHA-1 of DER: the identity Windows
	// files the certificate under and module manifests pin
	// (signing.authenticode_thumbprint).
	Thumbprint string
	Subject    string
}

// Load reads and parses a certificate file.
func Load(path string) (*Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certtrust: reading %s: %w", path, err)
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse accepts one certificate, PEM or DER, of the shape described in the
// package comment.
func Parse(raw []byte) (*Certificate, error) {
	der := raw
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrNoCertificate
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoCertificate, err)
	}
	// CheckSignatureFrom would refuse a CA:false parent outright, so the
	// self-signature is checked directly.
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) ||
		cert.CheckSignature(
			cert.SignatureAlgorithm,
			cert.RawTBSCertificate,
			cert.Signature,
		) != nil {
		return nil, ErrNotSelfSigned
	}
	if cert.IsCA {
		return nil, ErrIsCA
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning ||
		len(cert.UnknownExtKeyUsage) != 0 {
		return nil, ErrNotCodeSigning
	}
	return &Certificate{DER: der, Thumbprint: Thumbprint(der), Subject: cert.Subject.String()}, nil
}

// Thumbprint is the upper-case hex SHA-1 of a DER certificate.
func Thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // see the import
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// ValidThumbprint reports whether s is 40 hex digits.
func ValidThumbprint(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha1.Size
}
