package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

func openTest(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, keyprotect.New())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTripAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)

	secret := []byte("the smallest secret")
	if err := s.Put(context.Background(), "weave-linux-presence", "k", secret); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get(context.Background(), "weave-linux-presence", "k")
	if err != nil || !found || !bytes.Equal(got, secret) {
		t.Fatalf("get: %q %v %v", got, found, err)
	}
	s.Close()

	// Survives reopen with the same sealed key.
	s2 := openTest(t, dir)
	defer s2.Close()
	got, found, _ = s2.Get(context.Background(), "weave-linux-presence", "k")
	if !found || !bytes.Equal(got, secret) {
		t.Fatal("value lost across reopen")
	}
}

func TestCiphertextOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	plaintext := []byte("EXTREMELY-RECOGNIZABLE-PLAINTEXT-SENTINEL")
	if err := s.Put(context.Background(), "m", "k", plaintext); err != nil {
		t.Fatal(err)
	}
	s.Close()
	raw, err := os.ReadFile(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatal("plaintext visible in store file")
	}
}

func TestNamespaceIsolationInCiphertext(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	defer s.Close()
	if err := s.Put(context.Background(), "a", "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// The AAD binds namespace+key: the same ciphertext under another
	// namespace or key must not open.
	ct, err := s.seal("a", "k", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.open("b", "k", ct); err == nil {
		t.Fatal("ciphertext from namespace a opened under namespace b")
	}
	if _, err := s.open("a", "other", ct); err == nil {
		t.Fatal("ciphertext for key k opened under another key")
	}
}

func TestListAndDelete(t *testing.T) {
	s := openTest(t, t.TempDir())
	defer s.Close()
	s.Put(context.Background(), "m", "state/a", []byte("1")) //nolint:errcheck
	s.Put(context.Background(), "m", "state/b", []byte("2")) //nolint:errcheck
	s.Put(context.Background(), "m", "cache/c", []byte("3")) //nolint:errcheck
	keys, err := s.List(context.Background(), "m", "state/")
	if err != nil || len(keys) != 2 {
		t.Fatalf("list: %v %v", keys, err)
	}
	if err := s.Delete(context.Background(), "m", "state/a"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.Get(context.Background(), "m", "state/a"); found {
		t.Fatal("deleted key still present")
	}
}
