package manifest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Signing contexts provide domain separation: an endorsement signature and
// a manifest signature are over different message spaces, so a signature
// obtained in one role can never be replayed in the other. The signed
// message is Context + "\x00" + fileBytes.
const (
	EndorseContext  = "weave-endorse-v1"
	ManifestContext = "weave-manifest-v1"
)

// SigningMessage prepends the domain-separation context to the file bytes.
// Both signer and verifier must use the same context for a given role.
func SigningMessage(context string, data []byte) []byte {
	msg := make([]byte, 0, len(context)+1+len(data))
	msg = append(msg, context...)
	msg = append(msg, 0)
	return append(msg, data...)
}

// The signing chain is two-tier, minisign-shaped: an offline root key
// endorses named signing keys; signing keys sign channel manifests. All
// signatures are detached Ed25519 over the exact file bytes, stored
// beside the file as <name>.sig in this JSON format. Verification logic
// lives in internal/manifestverify; these are only the format types.

// Errors ParsePublicKey and ParseSignature report for a document that decodes
// but is not a usable key or signature.
var (
	ErrPublicKeyHeader = errors.New("public key: bad schema or key id")
	ErrPublicKeyBytes  = errors.New("public key: not a valid ed25519 key")
	ErrSignatureHeader = errors.New("signature: bad schema or key id")
	ErrSignatureBytes  = errors.New("signature: not a valid ed25519 signature")
)

// PublicKey is a stored public key (<name>.pub).
type PublicKey struct {
	Schema int    `json:"schema"`
	KeyID  string `json:"key_id"` //nolint:tagliatelle // signature file format shared with weavemanifest and weaveplatform-release-channels
	// Ed25519 public key, base64.
	PublicKey string `json:"public_key"` //nolint:tagliatelle // signature file format shared with weavemanifest and weaveplatform-release-channels
}

// Signature is a detached signature (<name>.sig).
type Signature struct {
	Schema int    `json:"schema"`
	KeyID  string `json:"key_id"` //nolint:tagliatelle // signature file format shared with weavemanifest and weaveplatform-release-channels
	// Ed25519 signature over the signed file's exact bytes, base64.
	Signature string `json:"signature"`
}

// ParsePublicKey decodes a stored public key and returns its raw bytes.
func ParsePublicKey(data []byte) (*PublicKey, []byte, error) {
	var pk PublicKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, nil, fmt.Errorf("public key: %w", err)
	}
	if pk.Schema != 1 || pk.KeyID == "" {
		return nil, nil, ErrPublicKeyHeader
	}
	raw, err := base64.StdEncoding.DecodeString(pk.PublicKey)
	if err != nil || len(raw) != 32 {
		return nil, nil, ErrPublicKeyBytes
	}
	return &pk, raw, nil
}

// ParseSignature decodes a detached signature and returns its raw bytes.
func ParseSignature(data []byte) (*Signature, []byte, error) {
	var sig Signature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, nil, fmt.Errorf("signature: %w", err)
	}
	if sig.Schema != 1 || sig.KeyID == "" {
		return nil, nil, ErrSignatureHeader
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(raw) != 64 {
		return nil, nil, ErrSignatureBytes
	}
	return &sig, raw, nil
}
