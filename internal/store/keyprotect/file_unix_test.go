//go:build !windows

package keyprotect

import (
	"bytes"
	"testing"
)

// The unix protector is deliberately the identity: the 0600 keyfile's
// permissions are the gate. A transform here would need a key of its own,
// stored beside the one it protects.
func TestFileProtectorIsTheIdentity(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	p := New()
	sealed, err := p.Seal(key)
	if err != nil || !bytes.Equal(sealed, key) {
		t.Fatalf("Seal = %x, %v", sealed, err)
	}
	got, err := p.Unseal(sealed)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("Unseal = %x, %v", got, err)
	}
}
