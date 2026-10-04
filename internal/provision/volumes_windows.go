package provision

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
)

// fileReadOnlyVolume is FILE_READ_ONLY_VOLUME from GetVolumeInformation's file
// system flags; the bindings do not carry it.
const fileReadOnlyVolume = 0x00080000

var errNoDrives = errors.New("no drives")

// Seams so tests can stand in for the drives.
var (
	logicalDrives = filesystem.GetLogicalDrives
	volumeInfo    = getVolumeInfo
)

// platformVolumes finds the drive whose volume label is WEAVEPROV. Windows
// mounts a volume under a letter, not a path, so every present letter is
// asked. The Go runtime runs with SEM_FAILCRITICALERRORS, so an empty
// removable drive answers with an error rather than a "insert a disk" prompt.
func platformVolumes() ([]string, error) {
	mask, err := logicalDrives()
	if mask == 0 {
		if err == nil {
			err = errNoDrives
		}
		return nil, fmt.Errorf("listing drives: %w", err)
	}
	var roots []string
	for i := range 26 {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		label, flags, err := volumeInfo(root)
		if err != nil || !strings.EqualFold(label, VolumeLabel) {
			continue
		}
		if flags&fileReadOnlyVolume == 0 {
			return nil, fmt.Errorf("%s: %w", root, errNotReadOnly)
		}
		roots = append(roots, root)
	}
	return roots, nil
}

func getVolumeInfo(root string) (label string, flags uint32, err error) {
	var name [261]uint16
	if err := filesystem.GetVolumeInformation(&root, &name[0], uint32(len(name)),
		nil, nil, &flags, nil, 0); err != nil {
		return "", 0, fmt.Errorf("GetVolumeInformation %s: %w", root, err)
	}
	return syscall.UTF16ToString(name[:]), flags, nil
}
