//go:build !windows

package provision

import (
	"fmt"
	"os"
)

// geteuid is a seam for the root-only branch.
var geteuid = os.Geteuid

// secureAnchor makes the anchor root's: 0644 root:wheel (root:root on Linux),
// readable by anyone and writable only by whoever may already change the
// guest's trust. An unprivileged core (a developer's run) leaves it its own.
func secureAnchor(path string) error {
	if geteuid() != 0 {
		return nil
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("chown root: %w", err)
	}
	return nil
}
