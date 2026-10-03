#!/bin/sh
# Stop the agent before its binaries go, and only when it is really going.
set -e

[ -d /run/systemd/system ] || exit 0

# "$1" is "upgrade" when this is the old version making way for a new one. Do not
# stop then: postinstall restarts it, and stopping here would take the guest's
# only channel to its host down for the length of the unpack.
if [ "$1" = "remove" ]; then
	systemctl stop weave-agent.service >/dev/null 2>&1 || true
	systemctl disable weave-agent.service >/dev/null 2>&1 || true
fi

exit 0
