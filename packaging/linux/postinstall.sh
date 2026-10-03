#!/bin/sh
# Enable and start the agent, the way dh_installsystemd would.
set -e

# /run/systemd/system exists only when systemd is PID 1. Without the guard this
# fails inside a container or a debootstrap chroot — both of which are how guest
# images get built, so the failure would land on image builds rather than on
# real installs.
[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable weave-agent.service >/dev/null 2>&1 || true

if [ -n "$2" ]; then
	# Upgrade: restart onto the new binaries. weaveboot's in-place core replace
	# handles a running core being swapped, but the package just replaced
	# weaveboot itself, and only a restart picks that up.
	systemctl restart weave-agent.service >/dev/null 2>&1 || true
else
	systemctl start weave-agent.service >/dev/null 2>&1 || true
fi

# Failure to start is not made fatal — dpkg would leave the package half-
# configured and every later apt operation would refuse to proceed. Check it with
#   systemctl status weave-agent
# and read the reason with
#   journalctl -u weave-agent
exit 0
