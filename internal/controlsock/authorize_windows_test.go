package controlsock

import (
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

// The pipe's SDDL is the gate on Windows; the authorizer must not second-guess
// it with a uid it does not have.
func TestControlAuthorizerDefersToThePipeACL(t *testing.T) {
	if err := controlAuthorizer()(ipc.PeerCred{}); err != nil {
		t.Fatal(err)
	}
}
