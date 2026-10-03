//go:build !windows

package layout

import (
	"os"
	"path/filepath"
	"testing"
)

// MkdirAll does not chmod an existing directory; Ensure must, or an
// installer's 0755 StateDir silently opens the store and sockets.
func TestEnsureTightensAPreexistingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(root).Ensure(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("StateDir mode %04o, want 0700", fi.Mode().Perm())
	}
}

// A directory the process does not own cannot be tightened, and Ensure must
// say so rather than carry on with a state root it could not secure. "/" is
// such a directory for any unprivileged run.
func TestEnsureReportsAFailedTighten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can chmod /; needs an unprivileged run")
	}
	if err := (Layout{StateDir: "/"}).Ensure(); err == nil {
		t.Fatal("Ensure claimed to tighten a directory it does not own")
	}
}
