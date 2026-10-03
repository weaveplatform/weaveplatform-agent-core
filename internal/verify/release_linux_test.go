//go:build !dev && linux

package verify

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On Linux, dpkg establishes provenance at install; core's exec-time job is to
// confirm nothing has become writable by a non-root party since. These tests
// run unprivileged, so the files are owned by the test user rather than root —
// which is itself one of the conditions that must be refused.

func TestLinuxVerifierRefusesNonRootOwnedBinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged run to produce a non-root-owned file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "weave-linux-exec")
	if err := os.WriteFile(path, []byte("module"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := newVerifier(nil).Verify(path, nil)
	if err == nil {
		t.Fatal("a module owned by a non-root user was accepted")
	}
	if !strings.Contains(err.Error(), "not root") {
		t.Fatalf("the refusal does not name the reason: %v", err)
	}
}

// A file that is root-owned and tight can still be swapped by anyone who can
// write the directory it sits in, so the directory is checked too. This is the
// case that a file-only check would miss.
func TestLinuxVerifierChecksTheContainingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "weave-linux-exec")
	if err := os.WriteFile(path, []byte("module"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := newVerifier(nil).Verify(path, nil); err == nil {
		t.Fatal("a module in a world-writable directory was accepted")
	}
}

func TestLinuxVerifierRefusesWorldWritableBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weave-linux-exec")
	if err := os.WriteFile(path, []byte("module"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: WriteFile's mode is filtered by the process umask, which
	// is 0022 in most environments, so the file would arrive 0755 and this test
	// would assert nothing. It still passed everywhere it was run, because those
	// runs were unprivileged and the verifier refused on OWNERSHIP before it ever
	// looked at the mode — so the mode branch has never actually been exercised
	// by this test until now. Core runs as root in production, where ownership
	// passes and the mode check is the only thing left.
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}

	err := newVerifier(nil).Verify(path, nil)
	if err == nil {
		t.Fatal("a world-writable module was accepted")
	}
	// Whichever condition it trips first, it must not be silent about it.
	if err.Error() == "" {
		t.Fatal("refused without saying why")
	}
}

func TestLinuxVerifierRefusesAMissingBinary(t *testing.T) {
	if err := newVerifier(nil).Verify(filepath.Join(t.TempDir(), "absent"), nil); err == nil {
		t.Fatal("a nonexistent module was accepted")
	}
}

// A root-owned 0755 binary in a root-owned 0755 directory is exactly what
// dpkg leaves behind, and must be accepted.
func TestLinuxVerifierAcceptsAPackageManagedBinary(t *testing.T) {
	const path = "/usr/bin/env"
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o022 != 0 {
		t.Skip("/usr/bin/env missing or not package-shaped here")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := newVerifier(log).Verify(path, nil); err != nil {
		t.Fatalf("a root-owned, root-only-writable binary was refused: %v", err)
	}
}

// The file passes on its own — it resolves to a root-owned binary — but the
// link lives in a directory its owner can rewrite, so the link can be
// repointed after the check. The directory check is what catches it.
func TestLinuxVerifierRefusesAPassingFileInAnUntrustedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged run to produce a non-root-owned directory")
	}
	link := filepath.Join(t.TempDir(), "weave-linux-exec")
	if err := os.Symlink("/usr/bin/env", link); err != nil {
		t.Fatal(err)
	}
	err := newVerifier(nil).Verify(link, nil)
	if err == nil || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("binary in a user-owned directory: %v", err)
	}
}

// Root ownership alone is not enough: /tmp is root's and writable by all.
func TestLinuxVerifierRefusesARootOwnedButWritablePath(t *testing.T) {
	err := rootOwnedAndUnwritable("/tmp")
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("/tmp: %v", err)
	}
}
