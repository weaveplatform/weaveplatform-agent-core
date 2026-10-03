//go:build !windows

package controlsock

import (
	"errors"
	"fmt"
	"os"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

// errNotAuthorized refuses a peer that is neither root nor core's own user.
var errNotAuthorized = errors.New("not authorized")

// controlAuthorizer permits only root or core's own user to drive the
// control service. A later per-user portal endpoint gets its own,
// group-scoped socket rather than loosening this one.
func controlAuthorizer() ipc.Authorizer {
	self := uint32(os.Getuid()) //nolint:gosec // G115: a POSIX uid_t is 32 bits, so Getuid fits
	return func(p ipc.PeerCred) error {
		if !p.HasUID {
			return nil
		}
		if p.UID == 0 || p.UID == self {
			return nil
		}
		return fmt.Errorf("control socket: peer uid %d %w", p.UID, errNotAuthorized)
	}
}
