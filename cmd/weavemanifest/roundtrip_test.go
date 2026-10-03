package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A manifest weavemanifest signs is one core accepts — literally, since
// verify is core's verifier. The round trip proves the tool's own output
// satisfies it, and that a flipped byte afterwards does not.
func TestSignVerifyGoldenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	signing := filepath.Join(dir, "signing")
	manifestPath := filepath.Join(dir, "manifest.json")

	// verify requires the endorsement to come from key id "root".
	if err := keygen([]string{"root", root}, io.Discard); err != nil {
		t.Fatalf("keygen root: %v", err)
	}
	if err := keygen([]string{"signing-2026", signing}, io.Discard); err != nil {
		t.Fatalf("keygen signing: %v", err)
	}

	// The verifier parses the payload after the signatures check out, so the
	// fixture must be a valid channel manifest, not just signed bytes.
	manifestJSON := []byte(
		`{"schema":1,"channel":"stable","sequence":1,"generated_at":"2026-08-10T00:00:00Z","expires":"2099-01-01T00:00:00Z","protocol":{"min":1,"max":1},"core":{"version":"0.1.0","artifacts":[]},"modules":[]}`,
	)
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := signFile([]string{root + ".key", signing + ".pub"}, true, io.Discard); err != nil {
		t.Fatalf("endorse: %v", err)
	}
	if err := signFile([]string{signing + ".key", manifestPath}, false, io.Discard); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}

	if err := verify(
		[]string{root + ".pub", signing + ".pub", manifestPath},
		io.Discard,
	); err != nil {
		t.Fatalf("verify of a freshly signed manifest failed: %v", err)
	}

	tampered := append([]byte{}, manifestJSON...)
	tampered[10] ^= 0xff
	if err := os.WriteFile(manifestPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify(
		[]string{root + ".pub", signing + ".pub", manifestPath},
		io.Discard,
	); err == nil {
		t.Fatal("verify accepted a tampered manifest")
	}
}
