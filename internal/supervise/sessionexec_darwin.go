package supervise

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// errPrivilegeRetained: after the drop the process is still, or could become
// again, someone other than the target identity.
var errPrivilegeRetained = errors.New("privilege retained after drop")

// errTooManyGroups: more supplementary groups than setgroups(2) accepts.
var errTooManyGroups = errors.New("too many groups")

// Seams over the credential and exec calls, which only root can exercise for
// real.
var (
	setgroups       = syscall.Setgroups
	setgid          = syscall.Setgid
	setuid          = syscall.Setuid
	getgroups       = syscall.Getgroups
	getuid          = syscall.Getuid
	getEffectiveUID = syscall.Geteuid
	getgid          = syscall.Getgid
	getegid         = syscall.Getegid
	execve          = syscall.Exec
)

func sessionExec(args []string, stderr io.Writer) int {
	if len(args) != 4 {
		fmt.Fprintln(stderr, "usage: weave-agent "+SessionExecCommand+" UID GID GROUPS BINARY")
		return 2
	}
	uid, gid, groups, err := parseIdentity(args[0], args[1], args[2])
	if err != nil {
		fmt.Fprintf(stderr, "weave-agent %s: %v\n", SessionExecCommand, err)
		return 2
	}
	bin := args[3]
	if !filepath.IsAbs(bin) {
		fmt.Fprintf(
			stderr,
			"weave-agent %s: binary %q is not an absolute path\n",
			SessionExecCommand,
			bin,
		)
		return 2
	}
	if err := dropTo(uid, gid, groups); err != nil {
		fmt.Fprintf(stderr, "weave-agent %s: %v\n", SessionExecCommand, err)
		return 1
	}
	err = execve(bin, []string{bin}, os.Environ())
	fmt.Fprintf(stderr, "weave-agent %s: exec %s: %v\n", SessionExecCommand, bin, err)
	return 1
}

// parseIdentity reads the drop target. uid 0 is refused: this mode exists to
// shed root, and a target of root would make it a way to keep it.
func parseIdentity(uidS, gidS, groupsS string) (uid, gid int, groups []int, err error) {
	ids := make([]int, 0, ngroupsMax+2)
	for _, s := range append([]string{uidS, gidS}, strings.Split(groupsS, ",")...) {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("id %q: %w", s, err)
		}
		ids = append(ids, int(n))
	}
	if ids[0] == 0 {
		return 0, 0, nil, fmt.Errorf("uid 0 is not a drop: %w", errPrivilegeRetained)
	}
	if len(ids)-2 > ngroupsMax {
		return 0, 0, nil, fmt.Errorf(
			"%w: %d, NGROUPS_MAX is %d",
			errTooManyGroups,
			len(ids)-2,
			ngroupsMax,
		)
	}
	return ids[0], ids[1], ids[2:], nil
}

// dropTo becomes uid/gid with exactly groups. Groups and gid go first: once
// the uid is not root, neither can be changed. setuid as root sets the real,
// effective and saved uid together, so nothing is left to switch back to —
// which is checked, not assumed, before the module gets the process.
func dropTo(uid, gid int, groups []int) error {
	if err := setgroups(groups); err != nil {
		return fmt.Errorf("setgroups %v: %w", groups, err)
	}
	if err := setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if getuid() != uid || getEffectiveUID() != uid || getgid() != gid || getegid() != gid {
		return fmt.Errorf("ids are %d/%d:%d/%d, want %d:%d: %w",
			getuid(), getEffectiveUID(), getgid(), getegid(), uid, gid, errPrivilegeRetained)
	}
	have, err := getgroups()
	if err != nil {
		return fmt.Errorf("getgroups: %w", err)
	}
	slices.Sort(have)
	want := slices.Clone(groups)
	slices.Sort(want)
	if !slices.Equal(slices.Compact(have), slices.Compact(want)) {
		return fmt.Errorf("groups are %v, want %v: %w", have, want, errPrivilegeRetained)
	}
	if setuid(0) == nil {
		return fmt.Errorf("setuid 0 still succeeds: %w", errPrivilegeRetained)
	}
	return nil
}
