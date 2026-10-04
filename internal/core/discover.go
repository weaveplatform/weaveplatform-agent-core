package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Discovery refusals, each recorded as the module's invalid detail.
var (
	errBadCurrent    = errors.New("current does not name a version directory")
	errIDMismatch    = errors.New("does not match its directory")
	errNoVersionDir  = errors.New("current names a version with no manifest")
	errUnreadableCfg = errors.New("config.json unreadable")
)

// moduleEntry is what one module directory holds, as far as running it goes.
type moduleEntry struct {
	spec supervise.Spec
	// invalid explains why the directory cannot run; empty when it can.
	invalid string
	// unsettled: the binary changed while it was being hashed. Something is
	// writing it in place, so the spec describes no file that exists.
	unsettled bool
}

// moduleDirs lists the candidate module directories under dir. A missing dir
// is an empty one; any other failure to read it is an error, because "could
// not look" must not be mistaken for "nothing installed" — a reload acting on
// that would stop every module.
func moduleDirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading modules dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// loadModule reads root/name in either layout: flat (manifest, binary and
// optional config.json in the directory) or versioned, as the lifecycle
// manager installs it (a `current` file naming versions/<v>). ok is false when
// the directory holds no module at all — no `current` and no manifest, as a
// package manager leaves it between creating it and unpacking into it.
//
// The binary is named after the module id (<id>.exe on Windows), or "module"
// as a fallback.
func loadModule(root, name string) (ent moduleEntry, ok bool) {
	mdir := filepath.Join(root, name)
	if fi, err := os.Stat(mdir); err != nil || !fi.IsDir() {
		return moduleEntry{}, false
	}
	versioned := false
	if cur, err := os.ReadFile(filepath.Join(mdir, "current")); err == nil {
		v := strings.TrimSpace(string(cur))
		if !isVersionDir(v) {
			return moduleEntry{invalid: fmt.Sprintf("%v: %q", errBadCurrent, v)}, true
		}
		mdir = filepath.Join(mdir, "versions", v)
		versioned = true
	}
	m, err := manifest.Load(filepath.Join(mdir, "module.manifest.json"))
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist) && versioned:
		return moduleEntry{
			invalid: fmt.Sprintf("%v: %s", errNoVersionDir, filepath.Base(mdir)),
		}, true
	case errors.Is(err, fs.ErrNotExist):
		return moduleEntry{}, false
	default:
		return moduleEntry{invalid: err.Error()}, true
	}
	// One name for a module everywhere: the registry, the lifecycle
	// manager's install tree and a module package all key on the id, and a
	// directory holding another id would be two modules fighting over one
	// entry.
	if m.ID != name {
		return moduleEntry{
			invalid: fmt.Sprintf("manifest id %q %v %q", m.ID, errIDMismatch, name),
		}, true
	}
	bin := ""
	for _, cand := range binaryCandidates(m.ID) {
		p := filepath.Join(mdir, cand)
		// p is built from the modules directory's own listing.
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() { //nolint:gosec // see above
			bin = p
			break
		}
	}
	if bin == "" {
		return moduleEntry{invalid: fmt.Sprintf("%v in %s", errNoBinary, mdir)}, true
	}
	var config []byte
	switch b, err := os.ReadFile(filepath.Join(mdir, "config.json")); { //nolint:gosec // see p above
	case err == nil:
		config = b
	case !errors.Is(err, fs.ErrNotExist):
		return moduleEntry{invalid: fmt.Sprintf("%v: %v", errUnreadableCfg, err)}, true
	}
	digest, settled, err := stableDigest(bin)
	if err != nil {
		return moduleEntry{invalid: err.Error()}, true
	}
	return moduleEntry{
		spec:      supervise.Spec{Manifest: m, BinPath: bin, Config: config, Digest: digest},
		unsettled: !settled,
	}, true
}

// stableDigest hashes path and reports whether the file was the same file,
// unchanged, before and after. A package manager renames a finished file into
// place, which is atomic, but a plain copy writes the binary where it will run;
// launching it halfway would exec a truncated binary, and recording its digest
// would make the finished one look like a change later.
func stableDigest(path string) (digest string, settled bool, err error) {
	// path is a binary discovery found by listing core's modules directory.
	before, err := os.Stat(path) //nolint:gosec // see above
	if err != nil {
		return "", false, fmt.Errorf("binary: %w", err)
	}
	digest, err = supervise.FileDigest(path)
	if err != nil {
		return "", false, fmt.Errorf("binary: %w", err)
	}
	after, err := os.Stat(path) //nolint:gosec // see before
	if err != nil {
		// Gone between the reads: replaced or removed mid-pass.
		return digest, false, nil
	}
	settled = os.SameFile(before, after) && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
	return digest, settled, nil
}
