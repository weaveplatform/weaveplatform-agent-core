#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Purge takes the state with it, and that is the intended reading of purge here:
# /var/lib/weave holds the device identity keypair and the device's policy.
# Leaving it behind means a later reinstall silently resumes being a device the
# operator believed they had removed — the store is encrypted, so nothing about
# the leftover directory would look like an identity to whoever found it.
if [ "$1" = "purge" ]; then
	rm -rf /var/lib/weave /var/log/weave /run/weave
fi

# The weave-agent account and group stay, even on purge, as Debian does with
# system accounts: files outside the package may still be owned by its uid,
# and deleting it would let a later account reuse that uid and inherit them.
# A reinstall adopts the existing account. Remove it by hand with
#   userdel weave-agent

exit 0
