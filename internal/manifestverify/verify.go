// Package manifestverify verifies the channel-manifest signing chain:
// the offline root key (embedded in core) endorses a signing key, the
// signing key signs the channel manifest. Deliberately in core rather
// than the SDK, so a CVE here is a core patch.
package manifestverify

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// Errors Verify returns when the chain does not hold, wrapped with detail.
var (
	// ErrNotRoot: the signing key's endorsement names a key other than root.
	ErrNotRoot = errors.New("not root")
	// ErrEndorsementInvalid: the root's endorsement signature does not verify.
	ErrEndorsementInvalid = errors.New("manifestverify: signing key endorsement invalid")
	// ErrKeyMismatch: the manifest names a signing key other than the endorsed one.
	ErrKeyMismatch = errors.New("manifestverify: manifest signer is not the signing key")
	// ErrSignatureInvalid: the manifest signature does not verify.
	ErrSignatureInvalid = errors.New("manifestverify: manifest signature invalid")
)

// Bundle is everything a signed channel manifest travels with.
type Bundle struct {
	// Manifest is the channel manifest's exact bytes.
	Manifest []byte
	// ManifestSig is the detached signature over Manifest by SigningKey.
	ManifestSig []byte
	// SigningKey is the signing public key file's exact bytes.
	SigningKey []byte
	// SigningKeySig is the root's endorsement: a detached signature over
	// SigningKey's exact bytes.
	SigningKeySig []byte
}

// Verify checks the full chain against the trusted root public key and
// returns the parsed manifest. Any failure is terminal — there is no
// partial trust.
func Verify(rootPub ed25519.PublicKey, b Bundle) (*manifest.ChannelManifest, error) {
	// 1. Root endorses the signing key.
	endorsement, endorsementSig, err := manifest.ParseSignature(b.SigningKeySig)
	if err != nil {
		return nil, fmt.Errorf("manifestverify: endorsement: %w", err)
	}
	if endorsement.KeyID != "root" {
		return nil, fmt.Errorf(
			"manifestverify: signing key endorsed by %q, %w",
			endorsement.KeyID,
			ErrNotRoot,
		)
	}
	endorsed := manifest.SigningMessage(manifest.EndorseContext, b.SigningKey)
	if !ed25519.Verify(rootPub, endorsed, endorsementSig) {
		return nil, ErrEndorsementInvalid
	}

	// 2. The endorsed signing key signs the manifest.
	signingKey, signingKeyRaw, err := manifest.ParsePublicKey(b.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("manifestverify: signing key: %w", err)
	}
	sig, sigRaw, err := manifest.ParseSignature(b.ManifestSig)
	if err != nil {
		return nil, fmt.Errorf("manifestverify: manifest signature: %w", err)
	}
	if sig.KeyID != signingKey.KeyID {
		return nil, fmt.Errorf("%w: manifest signed by %q but signing key is %q",
			ErrKeyMismatch, sig.KeyID, signingKey.KeyID)
	}
	signed := manifest.SigningMessage(manifest.ManifestContext, b.Manifest)
	if !ed25519.Verify(ed25519.PublicKey(signingKeyRaw), signed, sigRaw) {
		return nil, ErrSignatureInvalid
	}

	// 3. Only now parse the payload.
	ch, err := manifest.ParseChannel(b.Manifest)
	if err != nil {
		return nil, fmt.Errorf("manifestverify: %w", err)
	}
	return ch, nil
}
