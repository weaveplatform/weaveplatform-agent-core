package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/manifestverify"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// signedChannel builds a real root→signing-key→manifest chain carrying one
// module entry, so these tests exercise the same path production does rather
// than a stub.
func signedChannel(t *testing.T, module map[string]any) (ed25519.PublicKey, manifestverify.Bundle) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signingKeyFile, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "signing-2026",
		"public_key": base64.StdEncoding.EncodeToString(signPub),
	})
	endorsement, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "root",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				rootPriv,
				manifest.SigningMessage(manifest.EndorseContext, signingKeyFile),
			),
		),
	})
	manifestBytes, _ := json.Marshal(map[string]any{
		"schema": 1, "channel": "stable", "generated_at": "2026-08-10T00:00:00Z",
		"protocol": map[string]int{"min": 1, "max": 1},
		"core":     map[string]any{"version": "0.1.0", "artifacts": []any{}},
		"modules":  []any{module},
	})
	manifestSig, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "signing-2026",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				signPriv,
				manifest.SigningMessage(manifest.ManifestContext, manifestBytes),
			),
		),
	})
	return rootPub, manifestverify.Bundle{
		Manifest:      manifestBytes,
		ManifestSig:   manifestSig,
		SigningKey:    signingKeyFile,
		SigningKeySig: endorsement,
	}
}

// binary writes a fake module binary and returns its path and sha256.
func binary(t *testing.T, content string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weave-linux-exec")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

// moduleEntry is the signed channel entry for the module under test.
func moduleEntry(digest string) map[string]any {
	return map[string]any{
		"id": "weave-linux-exec", "version": "0.1.0", "protocol": 1,
		"privilege": "system", "session": "system",
		"capabilities": []string{"hypervisor.channel"},
		"artifacts": []any{map[string]any{
			"os": runtime.GOOS, "arch": runtime.GOARCH,
			"url": "https://example.invalid/weave-linux-exec", "digest": digest, "size": 1,
		}},
	}
}

// onDiskManifest is what core.discoverModules would load from beside the
// binary — the untrusted half.
func onDiskManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Schema: 1, ID: "weave-linux-exec", Version: "0.1.0", Protocol: 1,
		Zone: "A", Privilege: "system", Session: "system",
		Capabilities: []string{"hypervisor.channel"},
	}
}

func TestChannelVerifierAcceptsTheSignedBinary(t *testing.T) {
	path, digest := binary(t, "the real module")
	rootPub, bundle := signedChannel(t, moduleEntry(digest))

	v, err := NewChannel(nil, rootPub, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(path, onDiskManifest()); err != nil {
		t.Fatalf("the signed binary was refused: %v", err)
	}
}

// The whole point: a binary that is not the one the channel signed must be
// refused, however plausible everything around it looks.
func TestChannelVerifierRefusesATamperedBinary(t *testing.T) {
	_, digest := binary(t, "the real module")
	tampered, _ := binary(t, "something else entirely")
	rootPub, bundle := signedChannel(t, moduleEntry(digest))

	v, err := NewChannel(nil, rootPub, bundle)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(tampered, onDiskManifest())
	if err == nil {
		t.Fatal("a binary the channel never signed was accepted")
	}
	if !strings.Contains(err.Error(), "the channel signs") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// The manifest sits in the same directory as the binary, so an attacker who can
// replace one can rewrite the other. Rewriting it to ask for more authority
// must be refused rather than obeyed — core reads these fields to decide
// whether to run the module as root.
func TestChannelVerifierRefusesPrivilegeEscalationInTheOnDiskManifest(t *testing.T) {
	path, digest := binary(t, "the real module")
	entry := moduleEntry(digest)
	entry["privilege"] = "service" // what the channel actually grants
	rootPub, bundle := signedChannel(t, entry)

	v, err := NewChannel(nil, rootPub, bundle)
	if err != nil {
		t.Fatal(err)
	}

	escalated := onDiskManifest() // still claims privilege: system
	err = v.Verify(path, escalated)
	if err == nil {
		t.Fatal("a manifest claiming more privilege than the channel grants was accepted")
	}
	if !strings.Contains(err.Error(), "privilege") {
		t.Fatalf("the refusal does not name the reason: %v", err)
	}
}

func TestChannelVerifierRefusesUngrantedCapability(t *testing.T) {
	path, digest := binary(t, "the real module")
	entry := moduleEntry(digest)
	entry["capabilities"] = []string{} // the channel grants none
	rootPub, bundle := signedChannel(t, entry)

	v, _ := NewChannel(nil, rootPub, bundle)
	err := v.Verify(path, onDiskManifest())
	if err == nil {
		t.Fatal("a module requiring an ungranted capability was accepted")
	}
	if !strings.Contains(err.Error(), "capability") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestChannelVerifierRefusesUnknownModuleAndWrongVersion(t *testing.T) {
	path, digest := binary(t, "the real module")
	rootPub, bundle := signedChannel(t, moduleEntry(digest))
	v, _ := NewChannel(nil, rootPub, bundle)

	unknown := onDiskManifest()
	unknown.ID = "not-in-the-channel"
	if err := v.Verify(path, unknown); err == nil {
		t.Error("a module absent from the channel was accepted")
	}

	wrongVersion := onDiskManifest()
	wrongVersion.Version = "9.9.9"
	if err := v.Verify(path, wrongVersion); err == nil {
		t.Error("a version the channel did not sign was accepted")
	}
}

// A guest running a different architecture must not fall back to some other
// platform's digest.
func TestChannelVerifierRefusesWhenNoArtifactMatchesThisPlatform(t *testing.T) {
	path, digest := binary(t, "the real module")
	entry := moduleEntry(digest)
	entry["artifacts"] = []any{map[string]any{
		"os": "plan9", "arch": "mips", "url": "https://example.invalid/x",
		"digest": digest, "size": 1,
	}}
	rootPub, bundle := signedChannel(t, entry)

	v, _ := NewChannel(nil, rootPub, bundle)
	if err := v.Verify(path, onDiskManifest()); err == nil {
		t.Fatal("a module with no artifact for this platform was accepted")
	}
}

// A manifest that does not chain to the trusted root is a startup failure, not
// a per-module one — there is nothing to verify against.
func TestChannelVerifierRefusesABundleThatDoesNotChainToTheRoot(t *testing.T) {
	_, digest := binary(t, "the real module")
	_, bundle := signedChannel(t, moduleEntry(digest))

	otherRoot, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewChannel(nil, otherRoot, bundle); err == nil {
		t.Fatal("a bundle signed by an unknown root was accepted")
	}
}
