//go:build !dev

package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	crypt "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/wintrust"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Refusals from the Windows verifier, each the fixed part of its message.
var (
	errNoSubjectPin       = errors.New("pins no authenticode_subject; refusing")
	errWinVerifyTrust     = errors.New("WinVerifyTrust rejected")
	errNoProviderData     = errors.New("no provider data from trust state")
	errNoSigner           = errors.New("no signer in trust chain")
	errNoLeaf             = errors.New("no leaf certificate in trust chain")
	errThumbprintMismatch = errors.New("leaf thumbprint does not match the manifest's pin")
	errNoSubjectName      = errors.New("certificate has no subject name")
	errSubjectMismatch    = errors.New("signer does not match the manifest's pin")
)

// subjectNameLen is the buffer, in UTF-16 units, for the leaf's display name.
const subjectNameLen = 512

// newVerifier (release, Windows).
func newVerifier(_ *slog.Logger) supervise.Verifier {
	return supervise.VerifierFunc(authenticodeVerify)
}

// authenticodeVerify authenticates a module binary on Windows: a full
// WinVerifyTrust chain validation (SmartScreen protects nobody here —
// modules are fetched after install), then the signing certificate's
// subject pinned against the manifest.
func authenticodeVerify(path string, m *manifest.Manifest) error {
	if m.Signing == nil || m.Signing.AuthenticodeSubject == "" {
		return fmt.Errorf("verify: manifest for %s %w", m.ID, errNoSubjectPin)
	}

	fileInfo := wintrust.WINTRUST_FILE_INFO{
		PcwszFilePath: foundation.PWSTR(win32.UTF16Ptr(path)),
	}
	fileInfo.CbStruct = uint32(unsafe.Sizeof(fileInfo))

	wtd := wintrust.WINTRUST_DATA{
		DwUIChoice: wintrust.WTD_UI_NONE,
		// Check revocation for the whole chain, but from cached CRLs only
		// (WTD_CACHE_ONLY_URL_RETRIEVAL): a device agent is often offline,
		// and a hard network revocation check would fail-closed on every
		// offline install. Cache-only still catches known-revoked certs.
		FdwRevocationChecks: wintrust.WTD_REVOKE_WHOLECHAIN,
		DwUnionChoice:       wintrust.WTD_CHOICE_FILE,
		DwStateAction:       wintrust.WTD_STATEACTION_VERIFY,
		DwProvFlags:         wintrust.WTD_CACHE_ONLY_URL_RETRIEVAL | wintrust.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
	}
	wtd.CbStruct = uint32(unsafe.Sizeof(wtd))
	// fileInfo is stored into a union modeled as a byte array, which the GC
	// does not scan as a pointer slot — so nothing keeps fileInfo (and its
	// UTF-16 path buffer) alive across the two WinVerifyTrustEx calls
	// without an explicit KeepAlive. The CLOSE call is NOT deferred, so the
	// KeepAlive at the end of the function covers the whole span.
	*(*unsafe.Pointer)(unsafe.Pointer(&wtd.Anonymous.Data[0])) = unsafe.Pointer(&fileInfo)

	status := wintrust.WinVerifyTrustEx(0, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, &wtd)

	verifyErr := error(nil)
	if status != 0 {
		verifyErr = fmt.Errorf("verify: %w %s: 0x%08x", errWinVerifyTrust, path,
			uint32(status)) //nolint:gosec // an HRESULT is printed as its bit pattern
	} else {
		verifyErr = pinLeaf(path, wtd.HWVTStateData, m)
	}

	// Release the trust state (whether verify passed or failed).
	wtd.DwStateAction = wintrust.WTD_STATEACTION_CLOSE
	wintrust.WinVerifyTrustEx(0, &wintrust.WINTRUST_ACTION_GENERIC_VERIFY_V2, &wtd)
	runtime.KeepAlive(&fileInfo)
	return verifyErr
}

// pinLeaf pins the leaf signing certificate against the manifest. It
// prefers the SHA-1 thumbprint (a stable identity) when the manifest
// provides one, and otherwise falls back to the subject display name (a CN
// string, which is not unique — hence the thumbprint is preferred).
func pinLeaf(path string, state foundation.HANDLE, m *manifest.Manifest) error {
	provData := wintrust.WTHelperProvDataFromStateData(state)
	if provData == nil {
		return fmt.Errorf("verify: %s: %w", path, errNoProviderData)
	}
	sgnr := wintrust.WTHelperGetProvSignerFromChain(provData, 0, false, 0)
	if sgnr == nil {
		return fmt.Errorf("verify: %s: %w", path, errNoSigner)
	}
	cert := wintrust.WTHelperGetProvCertFromChain(sgnr, 0)
	if cert == nil || cert.PCert == nil {
		return fmt.Errorf("verify: %s: %w", path, errNoLeaf)
	}
	return matchPin(path, cert.PCert, m)
}

// matchPin is pinLeaf's comparison, split from the trust-state walk so it
// can be tested against a certificate the test mints: a chain WinVerifyTrust
// accepts cannot be produced on a CI runner without installing a root.
func matchPin(path string, cert *crypt.CERT_CONTEXT, m *manifest.Manifest) error {
	if want := m.Signing.AuthenticodeThumbprint; want != "" {
		got, err := certThumbprint(cert)
		if err != nil {
			return fmt.Errorf("verify: %s: %w", path, err)
		}
		if !strings.EqualFold(got, want) {
			return fmt.Errorf("verify: %s leaf thumbprint %s, manifest pins %s: %w",
				path, got, want, errThumbprintMismatch)
		}
		return nil
	}

	// Fallback: subject display name.
	buf := make([]uint16, subjectNameLen)
	n := crypt.CertGetNameString(cert, crypt.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,
		foundation.PWSTR(&buf[0]), subjectNameLen)
	if n <= 1 {
		return fmt.Errorf("verify: %s: %w", path, errNoSubjectName)
	}
	subject := win32.UTF16ToString(&buf[0])
	if subject != m.Signing.AuthenticodeSubject {
		return fmt.Errorf(
			"verify: %s signed by %q, manifest pins %q: %w",
			path,
			subject,
			m.Signing.AuthenticodeSubject,
			errSubjectMismatch,
		)
	}
	return nil
}

// certThumbprint returns the leaf certificate's SHA-1 thumbprint as an
// upper-case hex string, read from the cert context's SHA1 hash property.
func certThumbprint(cert *crypt.CERT_CONTEXT) (string, error) {
	var size uint32
	if err := crypt.CertGetCertificateContextProperty(
		cert,
		crypt.CERT_SHA1_HASH_PROP_ID,
		nil,
		&size,
	); err != nil {
		return "", fmt.Errorf("reading thumbprint size: %w", err)
	}
	buf := make([]byte, size)
	if err := crypt.CertGetCertificateContextProperty(
		cert,
		crypt.CERT_SHA1_HASH_PROP_ID,
		unsafe.Pointer(&buf[0]),
		&size,
	); err != nil {
		return "", fmt.Errorf("reading thumbprint: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(buf[:size])), nil
}
