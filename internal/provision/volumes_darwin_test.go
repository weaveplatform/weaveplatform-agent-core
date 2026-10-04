package provision

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func withVolumeRoot(t *testing.T, root string) {
	t.Helper()
	old := volumeRoot
	volumeRoot = root
	t.Cleanup(func() { volumeRoot = old })
}

// "/" on macOS is the sealed system volume: a mount point, read-only, mounted
// by the system. It passes every check the provisioning volume must.
func TestCheckMountAcceptsASystemReadOnlyMount(t *testing.T) {
	if err := checkMount("/"); err != nil {
		t.Fatalf("checkMount(/) = %v", err)
	}
	withVolumeRoot(t, "/")
	roots, err := platformVolumes()
	if err != nil || len(roots) != 1 || roots[0] != "/" {
		t.Fatalf("platformVolumes = %v, %v", roots, err)
	}
}

// A plain directory at the volume path is not a volume: an unprivileged user
// cannot create one under /Volumes, but the check must not depend on that.
func TestCheckMountRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := checkMount(dir); !errors.Is(err, errNotMountPoint) {
		t.Fatalf("checkMount(dir) = %v", err)
	}
	withVolumeRoot(t, dir)
	if _, err := platformVolumes(); !errors.Is(err, errNotMountPoint) {
		t.Fatalf("platformVolumes = %v", err)
	}
}

func TestCheckMountAbsent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "WEAVEPROV")
	if err := checkMount(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("checkMount(missing) = %v", err)
	}
	withVolumeRoot(t, missing)
	if roots, err := platformVolumes(); err != nil || roots != nil {
		t.Fatalf("platformVolumes = %v, %v", roots, err)
	}
	if err := checkMount("bad\x00path"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("checkMount(NUL) = %v", err)
	}
}

// The data volume is a system mount, but writable: not what a host attaches.
func TestCheckMountRefusesAWritableMount(t *testing.T) {
	const data = "/System/Volumes/Data"
	if err := checkMount(data); !errors.Is(err, errNotReadOnly) {
		if errors.Is(err, errNotMountPoint) || errors.Is(err, fs.ErrNotExist) {
			t.Skipf("%s is not a separate mount here", data)
		}
		t.Fatalf("checkMount(%s) = %v", data, err)
	}
}

// What an unprivileged user in the guest can make: a read-only disk image
// labelled WEAVEPROV, attached with hdiutil. It is mounted with that user as
// owner, and refused.
func TestCheckMountRefusesAUserMountedImage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-attached image is a system mount")
	}
	if testing.Short() {
		t.Skip("attaches a disk image")
	}
	// Resolved: the temporary directory is under /var, a symlink to
	// /private/var, and statfs names the mount by its real path.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(dir, "prov.dmg")
	if out, err := exec.Command(
		"hdiutil",
		"create",
		"-quiet",
		"-size",
		"1m",
		"-fs",
		"HFS+",
		"-volname",
		VolumeLabel,
		"-format",
		"UDRO",
		"-srcfolder",
		volume(t, "x"),
		img,
	).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v: %s", err, out)
	}
	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("hdiutil", "attach", "-quiet", "-readonly", "-nobrowse",
		"-mountpoint", mnt, img).CombinedOutput(); err != nil {
		t.Skipf("hdiutil attach: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("hdiutil", "detach", "-quiet", "-force", mnt).Run() })
	if err := checkMount(mnt); !errors.Is(err, errUserMounted) {
		t.Fatalf("checkMount(user image) = %v", err)
	}
}
