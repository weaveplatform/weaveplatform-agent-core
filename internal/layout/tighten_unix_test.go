//go:build !windows

package layout

import (
	"os"
	"path/filepath"
	"testing"
)

// MkdirAll does not chmod an existing directory; Ensure must, in both
// directions: an installer's 0755 StateDir must lose its listing, and an
// older core's 0700 must open to traversal or dropped modules cannot exec.
func TestEnsureHoldsEachDirectoryAtItsMode(t *testing.T) {
	for _, pre := range []os.FileMode{0o755, 0o700, 0o777} {
		root := filepath.Join(t.TempDir(), "state")
		l := Resolve(root)
		for _, d := range l.dirs() {
			if err := os.MkdirAll(d.path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d.path, pre); err != nil {
				t.Fatal(err)
			}
		}
		if err := l.Ensure(); err != nil {
			t.Fatal(err)
		}
		for _, d := range l.dirs() {
			fi, err := os.Stat(d.path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != d.mode {
				t.Fatalf("from %04o: %s mode %04o, want %04o", pre, d.path, fi.Mode().Perm(), d.mode)
			}
		}
	}
}

// A fresh tree comes out the same as a repaired one: StateDir, RunDir and
// ExecDir search-only for others, everything else private.
func TestEnsureFreshTreeModes(t *testing.T) {
	l := Resolve(filepath.Join(t.TempDir(), "state"))
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		l.StateDir: 0o711, l.RunDir: 0o711, l.ExecDir: 0o711,
		l.LogDir: 0o700, l.StagingDir: 0o700, l.ModulesDir: 0o700,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s mode %04o, want %04o", path, fi.Mode().Perm(), want)
		}
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
