//go:build !windows

package layout

import (
	"fmt"
	"os"
)

// setDirMode holds a directory at mode whatever it pre-existed with. On
// Windows, ACLs (not mode bits) govern access and Go's chmod is a near-no-op,
// so that variant is a no-op and the installer sets the ACL.
func setDirMode(dir string, mode os.FileMode) error {
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("layout: set mode of %s: %w", dir, err)
	}
	return nil
}
