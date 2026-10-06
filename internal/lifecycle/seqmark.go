package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// SequenceFile is the name of the plain-file copy of the channel-manifest
// anti-rollback mark, directly in core's state directory.
//
// The mark lives in two places because the store is the one thing a template
// seal deliberately throws away: `weave seal` removes store.key and store.db
// so every clone mints its own identity, and a Windows clone could not unseal
// the template's DPAPI-bound key anyway. A mark kept only in the store would
// reset to zero on every clone, and a clone would then accept any older
// signed manifest. The file is not secret — a sequence number — so it needs
// the state directory's access control (root-only on Unix, SYSTEM and
// Administrators on Windows), not the store's encryption, and a seal keeps it.
const SequenceFile = "manifest.sequence"

// Refusals of the anti-rollback check itself, as distinct from a manifest
// that fails it.
var (
	errSeqMalformed   = errors.New("lifecycle: manifest sequence mark is malformed")
	errSeqUnavailable = errors.New("lifecycle: refusing channel manifests: " +
		"the anti-rollback mark cannot be read")
	errSeqPersist = errors.New("lifecycle: refusing channel manifest: " +
		"its sequence could not be recorded")
)

// Seams for failures a real filesystem will not produce on demand. Nothing
// but a test writes them.
var (
	seqCreateTemp = func(dir, pattern string) (seqTemp, error) { return os.CreateTemp(dir, pattern) }
	seqRename     = os.Rename
	seqSyncDir    = syncDir
)

// seqTemp is the part of *os.File the atomic write uses.
type seqTemp interface {
	Name() string
	Write(b []byte) (int, error)
	Chmod(mode os.FileMode) error
	Sync() error
	Close() error
}

// readSeqFile returns the mark in path. A missing file is 0: a fresh install,
// or one that predates the file, whose store copy (if any) still counts. A
// file that is there but does not hold a number is an error, never 0 — read as
// 0 it would reopen exactly the replay window the file exists to close.
func readSeqFile(path string) (uint64, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // core's own state directory
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("lifecycle: reading %s: %w", path, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", errSeqMalformed, path, err)
	}
	return n, nil
}

// writeSeqFile replaces path with n: a temp file in the same directory,
// synced, then renamed over it, then the directory synced. A crash leaves the
// old mark or the new one, never a truncated file — which readSeqFile would
// (rightly) refuse, stopping manifest acceptance until an operator looked.
func writeSeqFile(path string, n uint64) error {
	dir := filepath.Dir(path)
	tmp, err := seqCreateTemp(dir, ".manifest.sequence-*")
	if err != nil {
		return fmt.Errorf("lifecycle: writing %s: %w", path, err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: writing %s: %w", path, err)
	}
	if _, err := tmp.Write([]byte(strconv.FormatUint(n, 10) + "\n")); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: writing %s: %w", path, err)
	}
	if err := seqRename(name, path); err != nil {
		os.Remove(name) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: writing %s: %w", path, err)
	}
	return seqSyncDir(dir)
}

// syncDir makes a rename in dir durable. Windows has no directory handle to
// flush (FlushFileBuffers on one is refused); NTFS journals the rename.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) //nolint:gosec // core's own state directory
	if err != nil {
		return fmt.Errorf("lifecycle: syncing %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("lifecycle: syncing %s: %w", dir, err)
	}
	return nil
}

// storeSequence returns the store's copy of the mark. Not found is 0; an
// error or a value that is not a number fails closed, as the file does.
func (m *Manager) storeSequence(ctx context.Context) (uint64, error) {
	raw, found, err := m.SeqStore.Get(ctx, manifestSeqNamespace, "sequence")
	if err != nil {
		return 0, fmt.Errorf("lifecycle: reading the stored manifest sequence: %w", err)
	}
	if !found {
		return 0, nil
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: in the store: %w", errSeqMalformed, err)
	}
	return n, nil
}

// acceptSequence enforces and advances the anti-rollback mark for a manifest
// whose signature has already been checked. The mark is the larger of the
// file and the store copies, and an accept writes every copy that is below
// the new sequence — so neither is ever lowered, and the first accept after
// an upgrade from a store-only core (or after a seal removed the store)
// brings both up to date.
func (m *Manager) acceptSequence(ctx context.Context, seq uint64) error {
	var fileMark, storeMark uint64
	var err error
	if m.SeqFile != "" {
		if fileMark, err = readSeqFile(m.SeqFile); err != nil {
			m.Log.Error("refusing channel manifests: the anti-rollback mark file is unusable; "+
				"restore it or set it to the last accepted sequence",
				"path", m.SeqFile, "err", err)
			return fmt.Errorf("%w: %w", errSeqUnavailable, err)
		}
	}
	if m.SeqStore != nil {
		if storeMark, err = m.storeSequence(ctx); err != nil {
			m.Log.Error("refusing channel manifests: the stored anti-rollback mark is unusable",
				"err", err)
			return fmt.Errorf("%w: %w", errSeqUnavailable, err)
		}
	}
	last := max(fileMark, storeMark)
	if seq < last {
		return fmt.Errorf("%w: sequence %d is older than accepted %d", errSequence, seq, last)
	}
	// The file first: it is the copy a seal keeps.
	if m.SeqFile != "" && seq > fileMark {
		if err := writeSeqFile(m.SeqFile, seq); err != nil {
			return fmt.Errorf("%w: %w", errSeqPersist, err)
		}
	}
	if m.SeqStore != nil && seq > storeMark {
		if err := m.SeqStore.Put(
			ctx,
			manifestSeqNamespace,
			"sequence",
			[]byte(strconv.FormatUint(seq, 10)),
		); err != nil {
			return fmt.Errorf("%w: %w", errSeqPersist, err)
		}
	}
	return nil
}
