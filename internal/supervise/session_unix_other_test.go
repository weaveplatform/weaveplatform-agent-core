//go:build !windows && !darwin

package supervise

import (
	"slices"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// On Linux the session is credentials and environment, not a launcher.
func TestLinuxSessionCommandIsPlainExec(t *testing.T) {
	cmd, via := sessionCommand("/opt/mod", &session.Session{UID: 1000}, &creds{uid: 1000})
	if via || !slices.Equal(cmd.Args, []string{"/opt/mod"}) {
		t.Fatalf("args = %q via=%v", cmd.Args, via)
	}
}
