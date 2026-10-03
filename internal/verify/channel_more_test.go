package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelVerifierRefusesSessionAndProtocolMismatch(t *testing.T) {
	path, digest := binary(t, "the real module")
	rootPub, bundle := signedChannel(t, moduleEntry(digest))
	v, err := NewChannel(slog.New(slog.NewTextHandler(io.Discard, nil)), rootPub, bundle)
	if err != nil {
		t.Fatal(err)
	}

	session := onDiskManifest()
	session.Session = "user"
	if err := v.Verify(path, session); err == nil || !strings.Contains(err.Error(), "session") {
		t.Errorf("session mismatch: %v", err)
	}
	proto := onDiskManifest()
	proto.Protocol = 2
	if err := v.Verify(path, proto); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Errorf("protocol mismatch: %v", err)
	}
	if err := v.Verify(path, nil); err == nil {
		t.Error("a binary with no manifest was accepted")
	}
}

func TestDigestMatchesReportsUnreadableBinaries(t *testing.T) {
	if err := digestMatches(filepath.Join(t.TempDir(), "absent"), "sha256:x"); err == nil ||
		!strings.Contains(err.Error(), "opening") {
		t.Errorf("missing binary: %v", err)
	}
	// A directory opens but does not read.
	if err := digestMatches(t.TempDir(), "sha256:x"); err == nil {
		t.Error("a directory hashed as a binary")
	}
}

// writeBundle lays the signed bundle out as `weavemanifest sign` would, with
// the root key in a separate directory, as the trust model requires.
func writeBundle(
	t *testing.T,
	rootPub ed25519.PublicKey,
	keyID string,
	bundleParts map[string][]byte,
) (string, string) {
	t.Helper()
	rootPath := filepath.Join(t.TempDir(), "root.pub")
	rootJSON, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": keyID, "public_key": base64.StdEncoding.EncodeToString(rootPub),
	})
	if err := os.WriteFile(rootPath, rootJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range bundleParts {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return rootPath, dir
}

func TestNewChannelFromDir(t *testing.T) {
	path, digest := binary(t, "the real module")
	rootPub, bundle := signedChannel(t, moduleEntry(digest))
	parts := map[string][]byte{
		channelManifestFile: bundle.Manifest,
		channelSigFile:      bundle.ManifestSig,
		signingKeyFile:      bundle.SigningKey,
		signingKeySigFile:   bundle.SigningKeySig,
	}

	rootPath, dir := writeBundle(t, rootPub, "root", parts)
	v, err := NewChannelFromDir(nil, rootPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(path, onDiskManifest()); err != nil {
		t.Fatalf("signed binary refused via the directory bundle: %v", err)
	}

	// A signing key presented as the root would let the channel endorse
	// itself; only a key that says it is the root anchors the chain.
	notRoot, dir2 := writeBundle(t, rootPub, "signing-2026", parts)
	if _, err := NewChannelFromDir(
		nil,
		notRoot,
		dir2,
	); err == nil ||
		!strings.Contains(err.Error(), "not the root") {
		t.Errorf("non-root anchor: %v", err)
	}

	incomplete := map[string][]byte{channelManifestFile: bundle.Manifest}
	rootPath3, dir3 := writeBundle(t, rootPub, "root", incomplete)
	if _, err := NewChannelFromDir(
		nil,
		rootPath3,
		dir3,
	); err == nil ||
		!strings.Contains(err.Error(), "channel bundle") {
		t.Errorf("incomplete bundle: %v", err)
	}

	if _, err := NewChannelFromDir(nil, "", dir); err == nil {
		t.Error("a bundle with no anchor was accepted")
	}
	if _, err := NewChannelFromDir(nil, filepath.Join(t.TempDir(), "absent"), dir); err == nil {
		t.Error("a missing root key was accepted")
	}
	garbage := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(garbage, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChannelFromDir(nil, garbage, dir); err == nil {
		t.Error("an unparseable root key was accepted")
	}

	otherRoot, _, _ := ed25519.GenerateKey(rand.Reader)
	rootPath4, dir4 := writeBundle(t, otherRoot, "root", parts)
	if _, err := NewChannelFromDir(nil, rootPath4, dir4); err == nil {
		t.Error("a bundle that does not chain to the root was accepted")
	}
}
