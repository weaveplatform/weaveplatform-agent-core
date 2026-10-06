package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

var errInjected = errors.New("injected")

// fakeProtector seals by prefixing, so a test can hand Open a key of any
// shape, and fails on demand.
type fakeProtector struct {
	sealErr, unsealErr error
	unsealTo           []byte
}

func (f fakeProtector) Seal(key []byte) ([]byte, error) {
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	return append([]byte("sealed:"), key...), nil
}

func (f fakeProtector) Unseal(sealed []byte) ([]byte, error) {
	if f.unsealErr != nil {
		return nil, f.unsealErr
	}
	if f.unsealTo != nil {
		return f.unsealTo, nil
	}
	return bytes.TrimPrefix(sealed, []byte("sealed:")), nil
}

func writeKey(t *testing.T, dir string, sealed []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "store.key"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesAnUnusableMasterKey(t *testing.T) {
	t.Run("unseal fails", func(t *testing.T) {
		dir := t.TempDir()
		writeKey(t, dir, []byte("x"))
		if _, err := Open(
			dir,
			fakeProtector{unsealErr: errInjected},
		); !errors.Is(err, errInjected) || !errors.Is(err, ErrUnseal) {
			t.Fatalf("Open = %v", err)
		}
	})
	// A short key would still build a cipher (AES-128) and silently weaken
	// the store; it must be refused instead.
	t.Run("wrong length", func(t *testing.T) {
		dir := t.TempDir()
		writeKey(t, dir, []byte("x"))
		_, err := Open(dir, fakeProtector{unsealTo: make([]byte, 16)})
		if err == nil || !strings.Contains(err.Error(), "wrong length") {
			t.Fatalf("Open = %v", err)
		}
	})
	t.Run("unreadable key", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "store.key"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, fakeProtector{}); err == nil {
			t.Fatal("Open succeeded with a directory for a key file")
		}
	})
	t.Run("seal fails", func(t *testing.T) {
		if _, err := Open(
			t.TempDir(),
			fakeProtector{sealErr: errInjected},
		); !errors.Is(err, errInjected) {
			t.Fatalf("Open = %v", err)
		}
	})
	t.Run("no state dir", func(t *testing.T) {
		if _, err := Open(filepath.Join(t.TempDir(), "absent"), fakeProtector{}); err == nil {
			t.Fatal("Open succeeded without its directory")
		}
	})
}

func TestOpenReportsDatabaseFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "store.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(
		dir,
		fakeProtector{},
	); err == nil ||
		!strings.HasPrefix(err.Error(), "store: ") {
		t.Fatalf("Open = %v", err)
	}
}

// A second core holding the same state dir must fail fast and say why,
// rather than hang on the flock.
func TestOpenFailsFastWhenLocked(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir, fakeProtector{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	start := time.Now()
	_, err = Open(dir, fakeProtector{})
	if err == nil || !strings.Contains(err.Error(), "locked by another weave-agent") {
		t.Fatalf("second Open = %v", err)
	}
	if waited := time.Since(start); waited > time.Minute {
		t.Fatalf("second Open waited %v", waited)
	}
}

// failingFile is a real temp file whose one named operation fails.
type failingFile struct {
	*os.File
	fail string
}

func (f failingFile) Write(b []byte) (int, error) {
	if f.fail == "write" {
		return 0, errInjected
	}
	return f.File.Write(b)
}

func (f failingFile) Chmod(m os.FileMode) error {
	if f.fail == "chmod" {
		return errInjected
	}
	return f.File.Chmod(m)
}

func (f failingFile) Close() error {
	err := f.File.Close()
	if f.fail == "close" {
		return errInjected
	}
	return err
}

// Every failure of the atomic key write must leave neither the key nor the
// temp file behind: a truncated key would make the store undecryptable, and
// a stray temp file would be picked up by nothing and leak the key.
func TestKeyWriteFailuresLeaveNothingBehind(t *testing.T) {
	for _, op := range []string{"create", "write", "chmod", "close", "rename"} {
		t.Run(op, func(t *testing.T) {
			dir := t.TempDir()
			oldCreate, oldRename := createTemp, rename
			t.Cleanup(func() { createTemp, rename = oldCreate, oldRename })
			createTemp = func(d, p string) (keyFile, error) {
				if op == "create" {
					return nil, errInjected
				}
				f, err := os.CreateTemp(d, p)
				if err != nil {
					return nil, err
				}
				return failingFile{File: f, fail: op}, nil
			}
			rename = func(string, string) error {
				if op == "rename" {
					return errInjected
				}
				return nil
			}
			if _, err := Open(dir, fakeProtector{}); !errors.Is(err, errInjected) {
				t.Fatalf("Open = %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("left behind %v", entries)
			}
		})
	}
}

func TestRandomnessFailureIsReported(t *testing.T) {
	old := randRead
	t.Cleanup(func() { randRead = old })
	randRead = func([]byte) (int, error) { return 0, errInjected }
	if _, err := Open(t.TempDir(), fakeProtector{}); !errors.Is(err, errInjected) {
		t.Fatalf("Open = %v", err)
	}

	randRead = old
	s := openTest(t, t.TempDir())
	defer s.Close()
	randRead = func([]byte) (int, error) { return 0, errInjected }
	if err := s.Put(context.Background(), "m", "k", []byte("v")); !errors.Is(err, errInjected) {
		t.Fatalf("Put = %v", err)
	}
}

func TestCancelledContextIsRefused(t *testing.T) {
	s := openTest(t, t.TempDir())
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Get(ctx, "m", "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("Get = %v", err)
	}
	if err := s.Put(ctx, "m", "k", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("Put = %v", err)
	}
	if err := s.Delete(ctx, "m", "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete = %v", err)
	}
	if _, err := s.List(ctx, "m", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("List = %v", err)
	}
}

func TestUnknownNamespaceAndKey(t *testing.T) {
	s := openTest(t, t.TempDir())
	defer s.Close()
	ctx := context.Background()
	if _, found, err := s.Get(ctx, "nobody", "k"); found || err != nil {
		t.Fatalf("Get(unknown ns) = %v, %v", found, err)
	}
	if err := s.Delete(ctx, "nobody", "k"); err != nil {
		t.Fatalf("Delete(unknown ns) = %v", err)
	}
	if keys, err := s.List(ctx, "nobody", ""); len(keys) != 0 || err != nil {
		t.Fatalf("List(unknown ns) = %v, %v", keys, err)
	}
	if err := s.Put(ctx, "m", "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Get(ctx, "m", "absent"); found || err != nil {
		t.Fatalf("Get(absent key) = %v, %v", found, err)
	}
}

func TestPutRejectsAnEmptyNamespace(t *testing.T) {
	s := openTest(t, t.TempDir())
	defer s.Close()
	if err := s.Put(context.Background(), "", "k", []byte("v")); err == nil {
		t.Fatal("Put into an unnamed namespace succeeded")
	}
}

// A value too short to hold a nonce is corruption, not a panic on slicing.
func TestGetReportsCorruptValues(t *testing.T) {
	s := openTest(t, t.TempDir())
	defer s.Close()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("m"))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), []byte("short"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(
		context.Background(),
		"m",
		"k",
	); err == nil ||
		!strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("Get = %v", err)
	}
}
