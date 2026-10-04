package provision

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

// volumeRoot is where macOS mounts a volume labelled WEAVEPROV. A second
// volume with the same label would mount as "WEAVEPROV 1" and is never looked
// at. A var so tests can point it elsewhere.
var volumeRoot = "/Volumes/" + VolumeLabel

var (
	errNotMountPoint = errors.New("not a mount point")
	errUserMounted   = errors.New("mounted by a user, not the system")
)

func platformVolumes() ([]string, error) {
	switch err := checkMount(volumeRoot); {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%s: %w", volumeRoot, err)
	}
	return []string{volumeRoot}, nil
}

// checkMount accepts path only as the root of a read-only filesystem that the
// system mounted.
//
// statfs, not the bindings: it is a bare BSD call, and DiskArbitration would
// answer the same question through a session and a callback.
//
// Each condition shuts out a way an unprivileged user in the guest could put a
// key there before the host's volume appears: /Volumes/WEAVEPROV as a plain
// directory is not a mount point; a disk image a user attaches (hdiutil allows
// it) is mounted with that user as its owner; and the host attaches the real
// one read-only, so a writable one is not it.
func checkMount(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fs.ErrNotExist
		}
		return fmt.Errorf("statfs: %w", err)
	}
	switch {
	case unix.ByteSliceToString(st.Mntonname[:]) != path:
		return errNotMountPoint
	case st.Flags&unix.MNT_RDONLY == 0:
		return errNotReadOnly
	case st.Owner != 0:
		return fmt.Errorf("%w (uid %d)", errUserMounted, st.Owner)
	}
	return nil
}
