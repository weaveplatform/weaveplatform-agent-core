package provision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeLinux points the lookup at a by-label directory whose WEAVEPROV entry
// names dev, and at mountinfo holding lines.
func fakeLinux(t *testing.T, dev string, lines string) {
	t.Helper()
	dir := t.TempDir()
	labels := filepath.Join(dir, "by-label")
	if err := os.Mkdir(labels, 0o755); err != nil {
		t.Fatal(err)
	}
	if dev != "" {
		if err := os.Symlink(dev, filepath.Join(labels, VolumeLabel)); err != nil {
			t.Fatal(err)
		}
	}
	info := filepath.Join(dir, "mountinfo")
	if lines != "-" {
		if err := os.WriteFile(info, []byte(lines), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldL, oldM := byLabelDir, mountInfoPath
	byLabelDir, mountInfoPath = labels, info
	t.Cleanup(func() { byLabelDir, mountInfoPath = oldL, oldM })
}

func TestLinuxVolumes(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "sr0")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const other = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"

	fakeLinux(t, "", other)
	if roots, err := platformVolumes(); err != nil || roots != nil {
		t.Fatalf("no label: %v, %v", roots, err)
	}

	fakeLinux(
		t,
		dev,
		other+"40 22 11:0 / /media/weave\\040prov ro,nosuid shared:9 - iso9660 "+dev+" ro\n",
	)
	roots, err := platformVolumes()
	if err != nil || len(roots) != 1 || roots[0] != "/media/weave prov" {
		t.Fatalf("mounted read-only: %v, %v", roots, err)
	}

	// Labelled but not mounted: core does not mount it.
	fakeLinux(t, dev, other)
	if roots, err := platformVolumes(); err != nil || roots != nil {
		t.Fatalf("not mounted: %v, %v", roots, err)
	}

	// A bind of a subdirectory is not the volume.
	fakeLinux(t, dev, other+"40 22 11:0 /weave /mnt ro - iso9660 "+dev+" ro\n")
	if roots, err := platformVolumes(); err != nil || roots != nil {
		t.Fatalf("subdirectory bind: %v, %v", roots, err)
	}

	fakeLinux(t, dev, other+"40 22 11:0 / /mnt rw - vfat "+dev+" rw\n")
	if _, err := platformVolumes(); !errors.Is(err, errNotReadOnly) {
		t.Fatalf("mounted read-write: %v", err)
	}

	fakeLinux(t, dev, "-")
	if _, err := platformVolumes(); err == nil {
		t.Fatal("unreadable mountinfo was not reported")
	}
}

func TestParseMountInfo(t *testing.T) {
	for _, bad := range []string{"", "1 2 3", "36 35 98:0 / /mnt rw - ext4", "36 35 98:0 / /mnt - ext4 /dev/x"} {
		if _, ok := parseMountInfo(bad); ok {
			t.Fatalf("parsed %q", bad)
		}
	}
	m, ok := parseMountInfo(
		"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue",
	)
	if !ok || m.root != "/mnt1" || m.point != "/mnt2" || m.source != "/dev/root" || m.readOnly {
		t.Fatalf("parsed %+v", m)
	}
	if got := unescapeMount(`a\040b\134c\09`); got != `a b\c\09` {
		t.Fatalf("unescape = %q", got)
	}
}
