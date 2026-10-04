//go:build !windows

package controlsock

import (
	"os"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

func TestControlAuthorizerAdmitsOnlyRootAndSelf(t *testing.T) {
	auth := controlAuthorizer()
	self := uint32(os.Getuid())
	for _, p := range []ipc.PeerCred{
		{UID: 0, HasUID: true},
		{UID: self, HasUID: true},
		// Platforms that cannot report a peer uid fall back to the 0600
		// socket file as the gate.
		{HasUID: false},
	} {
		if err := auth(p); err != nil {
			t.Errorf("%+v refused: %v", p, err)
		}
	}
	other := self + 4242
	if other == 0 {
		other++
	}
	if err := auth(ipc.PeerCred{UID: other, HasUID: true}); err == nil {
		t.Errorf("uid %d admitted", other)
	}
}
