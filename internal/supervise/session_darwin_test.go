package supervise

import (
	"slices"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// Without a drop the module still goes through launchctl asuser, for the
// GUI bootstrap, but nothing switches identity.
func TestDarwinSessionCommandNoDrop(t *testing.T) {
	cmd, via := sessionCommand("/opt/mod", &session.Session{UID: 501}, nil)
	if via || !slices.Equal(cmd.Args, []string{launchctlPath, "asuser", "501", "/opt/mod"}) {
		t.Fatalf("args = %q via=%v", cmd.Args, via)
	}
}

// The -G list leads with the primary group, skips its repeat, and stops at
// NGROUPS_MAX; an empty supplementary list still carries the primary group.
func TestDarwinGroupList(t *testing.T) {
	if got := groupList(&creds{gid: 20}); got != "20" {
		t.Fatalf("no supplementary groups: %q", got)
	}
	var many []uint32
	for g := uint32(100); g < 140; g++ {
		many = append(many, g)
	}
	got := strings.Split(groupList(&creds{gid: 20, groups: append([]uint32{20}, many...)}), ",")
	if len(got) != ngroupsMax || got[0] != "20" || got[1] != "100" {
		t.Fatalf("capped list = %v", got)
	}
}
