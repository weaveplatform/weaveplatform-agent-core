#!/bin/sh
# Checks the macOS package without installing it: the plist parses and runs
# weaveboot; postinstall, run dry against a stand-in dscl, creates the account
# idempotently and loads the daemon; uninstall removes what the package put
# down and nothing else; and, given binaries, the built package's payload is
# exactly the expected tree with the expected owners and modes.
#
#   packaging/darwin/package_test.sh [BIN_DIR]      (make package-test-darwin)
#
# It changes nothing on the machine it runs on: every command that would is
# printed instead (WEAVE_PKG_DRYRUN), and dscl's answers come from a stand-in.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bindir=${1:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# --- the plist
plist=$here/run.weaveplatform.agent.plist
plutil -lint "$plist" >/dev/null || fail "plist does not parse"
[ "$(plutil -extract Label raw "$plist")" = run.weaveplatform.agent ] || fail "label"
[ "$(plutil -extract ProgramArguments.0 raw "$plist")" = /usr/local/libexec/weave/weaveboot ] ||
	fail "the daemon must run weaveboot"
[ "$(plutil -extract ProgramArguments.3 raw "$plist")" = /usr/local/libexec/weave/modules ] ||
	fail "modules dir"
[ "$(plutil -extract KeepAlive raw "$plist")" = true ] || fail "KeepAlive"
[ "$(plutil -extract RunAtLoad raw "$plist")" = true ] || fail "RunAtLoad"

# --- postinstall, against a stand-in dscl: FAKE_USERS and FAKE_GROUPS are
# "name id" lines; -read answers from them, -list prints them.
cat >"$work/dscl" <<'SHIM'
#!/bin/sh
case "$2 $3" in
"-list /Users") printf '%s\n' "$FAKE_USERS" ;;
"-list /Groups") printf '%s\n' "$FAKE_GROUPS" ;;
"-read /Users/"*)
	id=$(printf '%s\n' "$FAKE_USERS" | awk -v n="${3#/Users/}" '$1 == n {print $2}')
	[ -n "$id" ] && echo "UniqueID: $id" ;;
"-read /Groups/"*)
	id=$(printf '%s\n' "$FAKE_GROUPS" | awk -v n="${3#/Groups/}" '$1 == n {print $2}')
	[ -n "$id" ] && echo "PrimaryGroupID: $id" ;;
*) echo "unexpected dscl $*" >&2; exit 3 ;;
esac
SHIM
chmod 0755 "$work/dscl"

post() {
	DSCL=$work/dscl LAUNCHCTL=/bin/launchctl WEAVE_PKG_DRYRUN=1 sh "$here/scripts/postinstall" pkg / "${1:-/}"
}
system_users='root 0
daemon 1
_taken 499'
system_groups='wheel 0
_taken 498'

# Fresh: one id free in both lists, used for the group and the user.
out=$(FAKE_USERS=$system_users FAKE_GROUPS=$system_groups post)
echo "$out" | grep -qx '+ .*/dscl . -create /Groups/_weaveagent PrimaryGroupID 497' || fail "fresh gid: $out"
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent UniqueID 497' || fail "fresh uid: $out"
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent UserShell /usr/bin/false' || fail "shell"
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent IsHidden 1' || fail "hidden"
echo "$out" | grep -qx '+ /bin/launchctl bootstrap system /Library/LaunchDaemons/run.weaveplatform.agent.plist' ||
	fail "daemon not loaded: $out"
echo "$out" | grep -qx '+ chmod 0750 /Library/Logs/Weave' || fail "log dir"

# A group left behind is adopted, its id reused for the user when free...
out=$(FAKE_USERS=$system_users FAKE_GROUPS="$system_groups
_weaveagent 460" post)
echo "$out" | grep -q 'create /Groups/' && fail "an existing group was recreated: $out"
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent UniqueID 460' || fail "adopted gid as uid: $out"
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent PrimaryGroupID 460' || fail "adopted gid: $out"

# ...and another free id when a user already has it.
out=$(FAKE_USERS="$system_users
_other 460" FAKE_GROUPS="$system_groups
_weaveagent 460" post)
echo "$out" | grep -qx '+ .*/dscl . -create /Users/_weaveagent UniqueID 497' || fail "uid clash: $out"

# Reinstall or upgrade: the account exists, nothing about it changes.
out=$(FAKE_USERS="$system_users
_weaveagent 460" FAKE_GROUPS="$system_groups
_weaveagent 460" post)
echo "$out" | grep -q 'dscl' && fail "an existing account was touched: $out"
echo "$out" | grep -qx '+ /bin/launchctl bootout system/run.weaveplatform.agent' || fail "upgrade must restart"

# Another volume: nothing on this system changes.
out=$(FAKE_USERS=$system_users FAKE_GROUPS=$system_groups post /Volumes/Image)
echo "$out" | grep -q '^+' && fail "changed the running system for another volume: $out"

# --- preinstall refuses a Mac of another architecture.
sed "s/@ARCH@/not-$(uname -m)/" "$here/scripts/preinstall" >"$work/preinstall"
if sh "$work/preinstall" 2>/dev/null; then fail "preinstall accepted the wrong architecture"; fi
sed "s/@ARCH@/$(uname -m)/" "$here/scripts/preinstall" >"$work/preinstall"
sh "$work/preinstall" || fail "preinstall refused this Mac"

# --- uninstall
out=$(WEAVE_PKG_DRYRUN=1 sh "$here/uninstall.sh")
echo "$out" | grep -qx '+ /bin/launchctl bootout system/run.weaveplatform.agent' || fail "uninstall: no bootout"
echo "$out" | grep -qx '+ rm -f /Library/LaunchDaemons/run.weaveplatform.agent.plist /usr/local/bin/weavectl' ||
	fail "uninstall: plist"
echo "$out" | grep -q 'Application Support' && fail "uninstall without --purge removed state"
echo "$out" | grep -q 'dscl' && fail "uninstall touched the account"
out=$(WEAVE_PKG_DRYRUN=1 sh "$here/uninstall.sh" --purge)
echo "$out" | grep -q '+ rm -rf /Library/Application Support/Weave' || fail "purge kept state"
if WEAVE_PKG_DRYRUN=1 sh "$here/uninstall.sh" --bogus 2>/dev/null; then fail "uninstall accepted a bad flag"; fi

# --- the built package
if [ -n "$bindir" ]; then
	pkg=$(sh "$here/build-pkg.sh" 0.0.0-test "$bindir" "$work/out" | tail -1)
	# ._* entries are a build machine's extended attributes (macOS tags files
	# a sandboxed process writes with com.apple.provenance); installer
	# restores them as attributes, not files. CI builds carry none.
	pkgutil --payload-files "$pkg" | grep -v '/\._' | sort >"$work/got"
	sort >"$work/want" <<'TREE'
.
./Library
./Library/LaunchDaemons
./Library/LaunchDaemons/run.weaveplatform.agent.plist
./usr
./usr/local
./usr/local/bin
./usr/local/bin/weavectl
./usr/local/libexec
./usr/local/libexec/weave
./usr/local/libexec/weave/modules
./usr/local/libexec/weave/uninstall.sh
./usr/local/libexec/weave/weave-agent
./usr/local/libexec/weave/weaveboot
./usr/local/libexec/weave/weavectl
./usr/local/libexec/weave/weavemanifest
TREE
	diff -u "$work/want" "$work/got" || fail "payload differs"
	pkgutil --expand "$pkg" "$work/exp"
	lsbom -p MUG "$work/exp/Bom" | grep -v '/\._' >"$work/bom"
	awk '$2 != "root" || $3 != "wheel" {bad=1; print} END {exit bad}' "$work/bom" || fail "payload not root:wheel"
	grep -q '^drwxr-xr-x' "$work/bom" || fail "bom unreadable"
	if grep -v '^drwxr-xr-x\|^-rwxr-xr-x\|^-rw-r--r--\|^lrwxr-xr-x' "$work/bom"; then fail "unexpected mode"; fi
	grep -qx 'want=arm64' "$work/exp/Scripts/preinstall" || fail "arch not substituted"
	[ -x "$work/exp/Scripts/postinstall" ] || fail "postinstall missing"
	echo "package: $(basename "$pkg") payload, owners, modes and scripts as expected"
fi
echo "darwin package scripts: ok"
