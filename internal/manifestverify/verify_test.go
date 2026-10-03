package manifestverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

func makeBundle(t *testing.T) (ed25519.PublicKey, Bundle) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signingKeyFile, _ := json.Marshal(map[string]any{ //nolint:errcheck
		"schema": 1, "key_id": "signing-2026",
		"public_key": base64.StdEncoding.EncodeToString(signPub),
	})
	endorsement, _ := json.Marshal(map[string]any{ //nolint:errcheck
		"schema": 1, "key_id": "root",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				rootPriv,
				manifest.SigningMessage(manifest.EndorseContext, signingKeyFile),
			),
		),
	})
	manifestBytes, _ := json.Marshal(map[string]any{ //nolint:errcheck
		"schema": 1, "channel": "stable", "generated_at": "2026-08-10T00:00:00Z",
		"protocol": map[string]int{"min": 1, "max": 1},
		"core":     map[string]any{"version": "0.1.0", "artifacts": []any{}},
		"modules":  []any{},
	})
	manifestSig, _ := json.Marshal(map[string]any{ //nolint:errcheck
		"schema": 1, "key_id": "signing-2026",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				signPriv,
				manifest.SigningMessage(manifest.ManifestContext, manifestBytes),
			),
		),
	})
	return rootPub, Bundle{
		Manifest:      manifestBytes,
		ManifestSig:   manifestSig,
		SigningKey:    signingKeyFile,
		SigningKeySig: endorsement,
	}
}

func TestVerifyChain(t *testing.T) {
	rootPub, b := makeBundle(t)
	ch, err := Verify(rootPub, b)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Channel != "stable" {
		t.Fatalf("channel = %s", ch.Channel)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	rootPub, b := makeBundle(t)

	tampered := b
	tampered.Manifest = append([]byte(nil), b.Manifest...)
	tampered.Manifest[len(tampered.Manifest)-2] ^= 1
	if _, err := Verify(rootPub, tampered); err == nil {
		t.Fatal("tampered manifest accepted")
	}

	wrongRoot, _, _ := ed25519.GenerateKey(rand.Reader) //nolint:errcheck
	if _, err := Verify(wrongRoot, b); err == nil {
		t.Fatal("bundle accepted under wrong root")
	}

	unendorsed := b
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader) //nolint:errcheck
	rogueKey, _ := json.Marshal(map[string]any{                //nolint:errcheck
		"schema": 1, "key_id": "signing-2026",
		"public_key": base64.StdEncoding.EncodeToString(otherPub),
	})
	unendorsed.SigningKey = rogueKey
	rogueSig, _ := json.Marshal(map[string]any{ //nolint:errcheck
		"schema": 1, "key_id": "signing-2026",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(otherPriv, manifest.SigningMessage(manifest.ManifestContext, b.Manifest))),
	})

	// Domain separation: a valid ROOT endorsement signature must not
	// verify as a MANIFEST signature (different context), even reusing the
	// same key material.
	crossCtx := b
	crossCtx.ManifestSig = b.SigningKeySig // endorsement sig in the manifest slot
	if _, err := Verify(rootPub, crossCtx); err == nil {
		t.Fatal("endorsement signature accepted as a manifest signature (no domain separation)")
	}
	unendorsed.ManifestSig = rogueSig
	if _, err := Verify(rootPub, unendorsed); err == nil {
		t.Fatal("rogue unendorsed signing key accepted")
	}
}
