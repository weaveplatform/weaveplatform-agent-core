#!/bin/sh
# Checks that postinstall.sh creates the weave-agent service account and is
# idempotent. It changes the system's accounts, so it runs in a throwaway
# container (make package-test), never on a workstation:
#
#   docker run --rm -v "$PWD/packaging/linux:/pkg:ro" ubuntu:24.04 sh /pkg/postinstall_test.sh
set -eu

pkg=$(dirname "$0")
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

check_account() {
	entry=$(getent passwd weave-agent) || fail "no weave-agent user"
	uid=$(echo "$entry" | cut -d: -f3)
	gid=$(echo "$entry" | cut -d: -f4)
	home=$(echo "$entry" | cut -d: -f6)
	shell=$(echo "$entry" | cut -d: -f7)
	[ "$uid" -lt 1000 ] || fail "uid $uid is not a system uid"
	[ "$shell" = /usr/sbin/nologin ] || fail "shell is $shell"
	[ "$home" = /nonexistent ] || fail "home is $home"
	[ ! -e /nonexistent ] || fail "a home directory was created"
	[ "$(getent group weave-agent | cut -d: -f3)" = "$gid" ] ||
		fail "primary group is not weave-agent"
}

# Fresh install: dpkg passes "configure" and no old version.
sh "$pkg/postinstall.sh" configure
check_account
first=$(getent passwd weave-agent)

# Reinstall and upgrade: nothing changes, nothing fails.
sh "$pkg/postinstall.sh" configure
sh "$pkg/postinstall.sh" configure 0.9.0
[ "$(getent passwd weave-agent)" = "$first" ] || fail "account changed on rerun"
[ "$(getent passwd | grep -c '^weave-agent:')" = 1 ] || fail "duplicate account"

# A group left behind without its user is adopted, not refused.
userdel weave-agent
[ -n "$(getent group weave-agent)" ] || groupadd --system weave-agent
sh "$pkg/postinstall.sh" configure
check_account

echo "postinstall: account created, idempotent"
