package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// kqueue reports a directory's entries changing, not which; these are the
// cases the snapshot and the per-file watches exist for.
func TestWatchKqueue(t *testing.T) {
	dir := t.TempDir()
	mdir := filepath.Join(dir, "m")
	writeFile(t, filepath.Join(mdir, "config.json"), "{}")
	writeFile(t, filepath.Join(mdir, "current"), "1.0.0")
	c := startWatch(t, dir)

	// A write in place: same inode, no directory change. Only the file's
	// own watch sees it.
	n := c.settle()
	f, err := os.OpenFile(filepath.Join(mdir, "config.json"), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"a":1}`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	c.waitAbove(t, n, "a file rewritten in place")

	// The lifecycle manager's flip: a hidden temporary renamed over
	// `current`. Writing the temporary is silent; the rename is not, though
	// no name came or went.
	n = c.settle()
	tmp := filepath.Join(mdir, ".tmp-123")
	writeFile(t, tmp, "2.0.0")
	if got := c.settle(); got != n {
		t.Fatalf("a hidden temporary notified (%d → %d)", n, got)
	}
	if err := os.Rename(tmp, filepath.Join(mdir, "current")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a rename over an existing name")

	// Installer-style debris at the top level is silent too.
	n = c.settle()
	writeFile(t, filepath.Join(dir, ".DS_Store"), "x")
	writeFile(t, filepath.Join(mdir, "._m"), "x")
	if got := c.settle(); got != n {
		t.Fatalf("dot-files notified (%d → %d)", n, got)
	}

	// A file removed from a module directory.
	n = c.settle()
	if err := os.Remove(filepath.Join(mdir, "config.json")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a removed file")
}

func TestIgnoredNameDarwin(t *testing.T) {
	for name, want := range map[string]bool{
		".tmp-1": true, "._weave": true, ".DS_Store": true, "m.dpkg-new": true,
		"weave-macos-presence": false, "module.manifest.json": false, "current": false,
	} {
		if ignoredName(name) != want {
			t.Errorf("ignoredName(%q) = %v", name, !want)
		}
	}
}

// A watch on a directory that is not there fails at once; one whose context
// is already over ends without error.
func TestWatchOnceEnds(t *testing.T) {
	if err := watchOnce(
		context.Background(),
		filepath.Join(t.TempDir(), "absent"),
		func() {},
	); err == nil {
		t.Fatal("watched a missing directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := watchOnce(ctx, t.TempDir(), func() {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("watchOnce after cancel = %v", err)
	}
}
