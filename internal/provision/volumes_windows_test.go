package provision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fakeDrives(t *testing.T, mask uint32, err error, vols map[string][2]any) {
	t.Helper()
	oldD, oldV := logicalDrives, volumeInfo
	logicalDrives = func() (uint32, error) { return mask, err }
	volumeInfo = func(root string) (string, uint32, error) {
		v, ok := vols[root]
		if !ok {
			return "", 0, errors.New("no medium")
		}
		return v[0].(string), v[1].(uint32), nil
	}
	t.Cleanup(func() { logicalDrives, volumeInfo = oldD, oldV })
}

func TestWindowsVolumes(t *testing.T) {
	const c, d, e = 1 << 2, 1 << 3, 1 << 4
	fakeDrives(t, c|d|e, nil, map[string][2]any{
		`C:\`: {"Windows", uint32(0)},
		`D:\`: {"weaveprov", uint32(fileReadOnlyVolume)},
	})
	roots, err := platformVolumes()
	if err != nil || len(roots) != 1 || roots[0] != `D:\` {
		t.Fatalf("read-only labelled drive: %v, %v", roots, err)
	}

	fakeDrives(t, c|d, nil, map[string][2]any{`D:\`: {"WEAVEPROV", uint32(0)}})
	if _, err := platformVolumes(); !errors.Is(err, errNotReadOnly) {
		t.Fatalf("writable labelled drive: %v", err)
	}

	fakeDrives(t, 0, nil, nil)
	if _, err := platformVolumes(); !errors.Is(err, errNoDrives) {
		t.Fatalf("no drives: %v", err)
	}
}

// The real calls, against this machine's system drive.
func TestGetVolumeInfo(t *testing.T) {
	mask, err := logicalDrives()
	if mask == 0 {
		t.Fatalf("GetLogicalDrives: %v", err)
	}
	sys := os.Getenv("SystemDrive") + `\`
	if _, _, err := getVolumeInfo(sys); err != nil {
		t.Fatalf("getVolumeInfo(%s): %v", sys, err)
	}
	if _, _, err := getVolumeInfo(`\\?\nowhere\`); err == nil {
		t.Fatal("no error for a volume that does not exist")
	}
}

// The anchor's ACL is applied to the staged file.
func TestSecureAnchorWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channel.pub")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := secureAnchor(path); err != nil {
		t.Fatal(err)
	}
	if err := secureAnchor(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("no error for a missing file")
	}
}
