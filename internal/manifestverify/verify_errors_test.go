package manifestverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// Each malformed or mislabelled part must stop the chain at its own step;
// there is no partial trust to fall back on.
func TestVerifyRefusesMalformedParts(t *testing.T) {
	rootPub, good := makeBundle(t)
	_, rootPriv, _ := ed25519.GenerateKey(rand.Reader)

	sigOf := func(keyID string, sig []byte) []byte {
		b, _ := json.Marshal(map[string]any{
			"schema": 1, "key_id": keyID, "signature": base64.StdEncoding.EncodeToString(sig),
		})
		return b
	}

	cases := map[string]struct {
		mutate func(*Bundle)
		want   string
	}{
		"endorsement unparseable": {
			func(b *Bundle) { b.SigningKeySig = []byte("{") },
			"endorsement",
		},
		// Only the root may endorse; a valid signature by any other key id
		// would let a signing key vouch for itself.
		"endorsed by non-root": {func(b *Bundle) {
			b.SigningKeySig = sigOf(
				"signing-2026",
				ed25519.Sign(
					rootPriv,
					manifest.SigningMessage(manifest.EndorseContext, b.SigningKey),
				),
			)
		}, "not root"},
		"signing key unparseable": {func(b *Bundle) {
			b.SigningKey = []byte("{")
			b.SigningKeySig = sigOf("root", make([]byte, 64))
		}, "endorsement invalid"},
		"manifest signature unparseable": {
			func(b *Bundle) { b.ManifestSig = []byte("{") },
			"manifest signature",
		},
		"manifest signed by another key id": {func(b *Bundle) {
			b.ManifestSig = sigOf("signing-other", make([]byte, 64))
		}, "but signing key is"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := good
			c.mutate(&b)
			if _, err := Verify(rootPub, b); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Verify = %v, want %q", err, c.want)
			}
		})
	}
}

// An endorsed signing key file that does not parse as a key is refused
// after the endorsement check, not trusted for having been endorsed.
func TestVerifyRefusesAnEndorsedButUnparseableSigningKey(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, b := makeBundle(t)
	b.SigningKey = []byte(`{"schema":1}`)
	endorsement, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "root",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(rootPriv, manifest.SigningMessage(manifest.EndorseContext, b.SigningKey))),
	})
	b.SigningKeySig = endorsement
	if _, err := Verify(rootPub, b); err == nil || !strings.Contains(err.Error(), "signing key:") {
		t.Fatalf("Verify = %v", err)
	}
}
