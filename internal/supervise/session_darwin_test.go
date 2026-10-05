package supervise

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/session"
)

// Without a drop the module still goes through launchctl asuser, for the
// GUI bootstrap, but nothing switches identity.
func TestDarwinSessionCommandNoDrop(t *testing.T) {
	cmd, via, err := sessionCommand("/opt/mod", &session.Session{UID: 501}, nil)
	if err != nil || via ||
		!slices.Equal(cmd.Args, []string{launchctlPath, "asuser", "501", "/opt/mod"}) {
		t.Fatalf("args = %q via=%v err=%v", cmd.Args, via, err)
	}
}

// With a drop, launchctl runs weave-agent's session-exec as root, and that
// drops; never chroot, which the kernel refuses a hardened-runtime binary.
func TestDarwinSessionCommandDrop(t *testing.T) {
	orig := selfExecutable
	t.Cleanup(func() { selfExecutable = orig })
	selfExecutable = func() (string, error) { return "/usr/local/libexec/weave/weave-agent", nil }
	cmd, via, err := sessionCommand("/opt/mod", &session.Session{UID: 501},
		&creds{uid: 501, gid: 20, groups: []uint32{12, 20, 80}})
	want := []string{
		launchctlPath, "asuser", "501", "/usr/local/libexec/weave/weave-agent",
		SessionExecCommand, "501", "20", "20,12,80", "/opt/mod",
	}
	if err != nil || !via || !slices.Equal(cmd.Args, want) {
		t.Fatalf("args = %q via=%v err=%v", cmd.Args, via, err)
	}
	for _, a := range cmd.Args {
		if strings.Contains(a, "chroot") {
			t.Fatalf("chroot in the launch: %q", cmd.Args)
		}
	}

	errGone := errors.New("gone")
	selfExecutable = func() (string, error) { return "", errGone }
	if _, _, err := sessionCommand(
		"/opt/mod",
		&session.Session{UID: 501},
		&creds{uid: 501},
	); !errors.Is(
		err,
		errGone,
	) {
		t.Fatalf("err = %v", err)
	}
}

// The group list leads with the primary group, skips its repeat, and stops at
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
