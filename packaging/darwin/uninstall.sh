#!/bin/sh
# Remove weave-agent from this Mac:
#
#   sudo /usr/local/libexec/weave/uninstall.sh [--purge]
#
# --purge also removes core's state (the device identity, store and policy)
# and its logs. WEAVE_PKG_DRYRUN=1 prints what would be done instead.
set -eu

LABEL=run.weaveplatform.agent
LIBEXEC=/usr/local/libexec/weave
LAUNCHCTL=${LAUNCHCTL:-/bin/launchctl}
PKGUTIL=${PKGUTIL:-/usr/sbin/pkgutil}
DRY=${WEAVE_PKG_DRYRUN:-}

run() {
	if [ -n "$DRY" ]; then
		echo "+ $*"
	else
		"$@"
	fi
}

purge=
case ${1:-} in
--purge) purge=1 ;;
"") ;;
*)
	echo "usage: $0 [--purge]" >&2
	exit 2
	;;
esac
if [ -z "$DRY" ] && [ "$(id -u)" != 0 ]; then
	echo "weave-agent: run as root (sudo $0)" >&2
	exit 1
fi

# Stops weaveboot, which drains core and the modules before exiting.
run "$LAUNCHCTL" bootout "system/$LABEL" 2>/dev/null || true
run rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/weavectl
for f in weaveboot weave-agent weavectl weavemanifest uninstall.sh; do
	run rm -f "$LIBEXEC/$f"
done
# Modules installed by their own packages stay where they are: removing core
# does not make them anyone else's to delete. With none left, the tree goes.
run rmdir "$LIBEXEC/modules" 2>/dev/null || echo "weave-agent: modules remain in $LIBEXEC/modules"
run rmdir "$LIBEXEC" 2>/dev/null || true
run "$PKGUTIL" --forget "$LABEL" >/dev/null 2>&1 || true

if [ -n "$purge" ]; then
	# The state holds the device identity: a reinstall that found it would
	# silently resume being a device the operator believed removed.
	run rm -rf "/Library/Application Support/Weave" /Library/Logs/Weave /var/run/weave
fi

# What stays, and why:
#  - the _weaveagent account and group. Files elsewhere may carry its uid, and
#    a freed uid could be handed to an account that would then own them. A
#    reinstall adopts it. Remove it by hand with
#      sudo dscl . -delete /Users/_weaveagent; sudo dscl . -delete /Groups/_weaveagent
#  - the channel trust anchor, /etc/weave/channel.pub. It is provisioning, not
#    the package's: removing it changes who may drive this guest.
echo "weave-agent: removed${purge:+, state purged}; the _weaveagent account and /etc/weave/channel.pub remain"
