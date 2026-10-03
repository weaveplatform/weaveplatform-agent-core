// Package store is core's durable, encrypted key/value store: one bbolt
// file owned by core, one bucket per module namespace, every value sealed
// with AES-256-GCM under a master key the platform protector guards.
// Modules cannot name, let alone read, each other's namespace — the
// namespace argument is bound at the hostserv seam, not chosen by callers.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

// Seams for failures a real filesystem and crypto/rand will not produce on
// demand. Nothing but a test writes them.
var (
	randRead   = rand.Read
	createTemp = func(dir, pattern string) (keyFile, error) { return os.CreateTemp(dir, pattern) }
	rename     = os.Rename
)

// Sentinel errors, wrapped with detail where there is any.
var (
	// ErrLocked: another weave-agent instance holds the database flock.
	ErrLocked = errors.New("store: database is locked by another weave-agent instance")
	// ErrKeyLength: the unsealed master key is not an AES-256 key.
	ErrKeyLength = errors.New("store: master key has wrong length")
	// ErrCorrupt: a stored value is too short to carry its nonce.
	ErrCorrupt = errors.New("store: corrupt value")
)

// keyFile is the part of *os.File the atomic key write uses.
type keyFile interface {
	Name() string
	Write(b []byte) (int, error)
	Chmod(mode os.FileMode) error
	Close() error
}

// Store implements hostserv.StoreBackend with encryption at rest.
type Store struct {
	db   *bolt.DB
	aead cipher.AEAD
}

// Open opens (creating if needed) the store at dir/store.db, with the
// master key at dir/store.key sealed by the protector.
func Open(dir string, protector keyprotect.Protector) (*Store, error) {
	key, err := loadOrCreateKey(filepath.Join(dir, "store.key"), protector)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("store: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("store: gcm: %w", err)
	}
	// Timeout so a second core instance (operator double-start, or
	// weaveboot restarting before the old core released the flock) fails
	// fast with a clear message instead of blocking forever.
	db, err := bolt.Open(
		filepath.Join(dir, "store.db"),
		0o600,
		&bolt.Options{Timeout: 2 * time.Second},
	)
	if err != nil {
		if errors.Is(err, bolterr.ErrTimeout) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{db: db, aead: aead}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

func loadOrCreateKey(path string, protector keyprotect.Protector) ([]byte, error) {
	if sealed, err := os.ReadFile(path); err == nil {
		key, err := protector.Unseal(sealed)
		if err != nil {
			return nil, fmt.Errorf("store: unsealing master key: %w", err)
		}
		if len(key) != 32 {
			return nil, ErrKeyLength
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("store: reading master key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("store: generating master key: %w", err)
	}
	sealed, err := protector.Seal(key)
	if err != nil {
		return nil, fmt.Errorf("store: sealing master key: %w", err)
	}
	// Atomic write: a crash mid-write must not leave a truncated key that
	// renders the entire store permanently undecryptable.
	tmp, err := createTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return nil, fmt.Errorf("store: writing master key: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("store: writing master key: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, fmt.Errorf("store: writing master key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("store: writing master key: %w", err)
	}
	// tmpName comes from os.CreateTemp and path is core-internal.
	if err := rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("store: writing master key: %w", err)
	}
	return key, nil
}

// seal encrypts value binding it to namespace and key: a ciphertext moved
// to another key or namespace fails to open.
func (s *Store) seal(module, key string, value []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return nil, fmt.Errorf("store: nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, value, aad(module, key)), nil
}

func (s *Store) open(module, key string, sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, ErrCorrupt
	}
	plain, err := s.aead.Open(nil, sealed[:ns], sealed[ns:], aad(module, key))
	if err != nil {
		return nil, fmt.Errorf("store: opening %s/%s: %w", module, key, err)
	}
	return plain, nil
}

func aad(module, key string) []byte {
	return []byte(module + "\x00" + key)
}

// Get implements hostserv.StoreBackend.
func (s *Store) Get(ctx context.Context, module, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("store: get: %w", err)
	}
	var out []byte
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(module))
		if b == nil {
			return nil
		}
		sealed := b.Get([]byte(key))
		if sealed == nil {
			return nil
		}
		plain, err := s.open(module, key, sealed)
		if err != nil {
			return err
		}
		out = plain
		found = true
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: get: %w", err)
	}
	return out, found, nil
}

// Put implements hostserv.StoreBackend.
func (s *Store) Put(ctx context.Context, module, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: put: %w", err)
	}
	sealed, err := s.seal(module, key, value)
	if err != nil {
		return err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(module))
		if err != nil {
			return fmt.Errorf("bucket: %w", err)
		}
		return b.Put([]byte(key), sealed)
	})
	if err != nil {
		return fmt.Errorf("store: put: %w", err)
	}
	return nil
}

// Delete implements hostserv.StoreBackend.
func (s *Store) Delete(ctx context.Context, module, key string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(module))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
	if err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// List implements hostserv.StoreBackend.
func (s *Store) List(ctx context.Context, module, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(module))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			if strings.HasPrefix(string(k), prefix) {
				keys = append(keys, string(k))
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	return keys, nil
}
