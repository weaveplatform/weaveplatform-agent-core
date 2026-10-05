package certtrust

import (
	"crypto/sha1" //nolint:gosec // only its Size: see certtrust.go
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	crypt "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"
)

const encoding = crypt.X509_ASN_ENCODING | crypt.PKCS_7_ASN_ENCODING

// cryptENotFound is CRYPT_E_NOT_FOUND as the last-error value
// CertFindCertificateInStore leaves: the HRESULT's bit pattern.
const cryptENotFound win32.Errno = 0x80092004

// errBadThumbprint is a thumbprint that is not 40 hex digits.
var errBadThumbprint = errors.New("certtrust: thumbprint is not 40 hex digits")

// Trust adds c to every store in Stores at loc, replacing a copy already
// there, so a re-install converges rather than failing.
func Trust(loc Location, c *Certificate) error {
	for _, name := range Stores {
		if err := withStore(loc, name, func(s crypt.HCERTSTORE) error {
			if err := crypt.CertAddEncodedCertificateToStore(
				s, encoding, c.DER, crypt.CERT_STORE_ADD_REPLACE_EXISTING, nil,
			); err != nil {
				return fmt.Errorf("adding %s: %w", c.Thumbprint, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// Untrust removes the certificate with this thumbprint from every store in
// Stores at loc. Absent is not an error: the result is the same.
func Untrust(loc Location, thumbprint string) error {
	for _, name := range Stores {
		if err := withStore(loc, name, func(s crypt.HCERTSTORE) error {
			for {
				ctx, err := find(s, thumbprint)
				if err != nil || ctx == nil {
					return err
				}
				// Frees ctx whether or not it succeeds.
				if err := crypt.CertDeleteCertificateFromStore(ctx); err != nil {
					return fmt.Errorf("removing %s: %w", thumbprint, err)
				}
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

// Trusted reports, per store in Stores, whether the certificate with this
// thumbprint is in it at loc.
func Trusted(loc Location, thumbprint string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, name := range Stores {
		if err := withStore(loc, name, func(s crypt.HCERTSTORE) error {
			ctx, err := find(s, thumbprint)
			if ctx != nil {
				crypt.CertFreeCertificateContext(ctx)
				out[name] = true
			}
			return err
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// find returns the store's certificate with this thumbprint, nil when there
// is none.
func find(s crypt.HCERTSTORE, thumbprint string) (*crypt.CERT_CONTEXT, error) {
	hash, err := hex.DecodeString(thumbprint)
	if err != nil || len(hash) != sha1.Size {
		return nil, fmt.Errorf("%w: %q", errBadThumbprint, thumbprint)
	}
	blob := crypt.CRYPT_INTEGER_BLOB{CbData: sha1.Size, PbData: &hash[0]}
	ctx, err := crypt.CertFindCertificateInStore(
		s, encoding, 0, crypt.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil,
	)
	if ctx != nil {
		return ctx, nil
	}
	var errno win32.Errno
	if errors.As(err, &errno) && errno == cryptENotFound {
		return nil, nil //nolint:nilnil // nil, nil is "not there", which callers ask for
	}
	return nil, fmt.Errorf("searching for %s: %w", thumbprint, err)
}

// withStore opens one system store for writing and closes it after fn.
func withStore(loc Location, name string, fn func(crypt.HCERTSTORE) error) error {
	flags := crypt.CERT_SYSTEM_STORE_LOCAL_MACHINE
	if loc == CurrentUser {
		flags = crypt.CERT_SYSTEM_STORE_CURRENT_USER
	}
	// The system store provider by name (sz_CERT_STORE_PROV_SYSTEM_W, whose
	// pvPara is a UTF-16 store name) rather than by its number: wincrypt.h
	// passes CERT_STORE_PROV_SYSTEM_W as the integer 10 cast to a pointer,
	// which Go's checkptr rightly refuses as a pointer value.
	provider := append([]byte(crypt.Sz_CERT_STORE_PROV_SYSTEM_W), 0)
	s, err := crypt.CertOpenStore(
		foundation.PSTR(&provider[0]), 0,
		crypt.CERT_OPEN_STORE_FLAGS(flags)|crypt.CERT_STORE_OPEN_EXISTING_FLAG,
		unsafe.Pointer(win32.UTF16Ptr(name)),
	)
	if err != nil {
		return fmt.Errorf("certtrust: opening %s\\%s (is this elevated?): %w", loc, name, err)
	}
	// Nothing to do about a failed close of a system store.
	defer func() { _ = crypt.CertCloseStore(s, 0) }()
	if err := fn(s); err != nil {
		return fmt.Errorf("certtrust: %s\\%s: %w", loc, name, err)
	}
	return nil
}
