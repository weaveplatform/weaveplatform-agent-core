package keyprotect

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestDPAPIRoundTrip is a Windows-host handoff test: seal then unseal a key
// and confirm it survives, and that the sealed blob is not the plaintext.
// Run on Windows: `go test ./internal/store/keyprotect/`.
func TestDPAPIRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p := New()
	sealed, err := p.Seal(key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, key) {
		t.Fatal("sealed blob contains the plaintext key")
	}
	got, err := p.Unseal(sealed)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unsealed key differs from original")
	}
}

// TestDPAPIEntropyBinding confirms that a blob sealed with the machine
// entropy cannot be unsealed without it — i.e. entropy is actually applied.
// If this fails, the secondary-entropy binding regressed to machine-scope
// only (any local process could unseal).
func TestDPAPIEntropyBinding(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	sealed, err := New().Seal(key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Unseal with WRONG entropy must fail. We reach past the public API to
	// prove entropy is in play.
	_, err = dpapi(sealed, []byte("not-the-machine-guid"), unsealOp)
	if err == nil {
		t.Fatal("unseal succeeded with wrong entropy; secondary entropy is not applied")
	}
}

func TestDPAPIRefusesEmptyInput(t *testing.T) {
	if _, err := New().Seal(nil); err == nil {
		t.Fatal("sealed an empty key")
	}
	if _, err := New().Unseal(nil); err == nil {
		t.Fatal("unsealed an empty blob")
	}
}

// Garbage is not a DPAPI blob; the API error must surface, not an empty key.
func TestDPAPIUnsealRejectsGarbage(t *testing.T) {
	if key, err := New().Unseal([]byte("not a dpapi blob")); err == nil {
		t.Fatalf("unsealed garbage to %x", key)
	}
}

// Without the machine entropy there is nothing to bind the blob to; both
// directions must fail rather than fall back to machine scope alone.
func TestDPAPIFailsClosedWithoutEntropy(t *testing.T) {
	for name, set := range map[string]func(){
		"missing key":   func() { entropyKey = `SOFTWARE\Weave\NoSuchCryptographyKey` },
		"missing value": func() { entropyValue = "NoSuchMachineGuid" },
	} {
		t.Run(name, func(t *testing.T) {
			oldKey, oldValue := entropyKey, entropyValue
			t.Cleanup(func() { entropyKey, entropyValue = oldKey, oldValue })
			set()
			if _, err := New().Seal([]byte("k")); err == nil {
				t.Error("sealed without entropy")
			}
			if _, err := New().Unseal([]byte("k")); err == nil {
				t.Error("unsealed without entropy")
			}
		})
	}
}
