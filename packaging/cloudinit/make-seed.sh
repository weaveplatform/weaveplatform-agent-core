#!/bin/sh
# Build a NoCloud seed ISO that installs weave-agent at first boot.
#
#   ./packaging/cloudinit/make-seed.sh <vm> <repo-url> <archive-key> [out.iso]
#
# e.g. ./packaging/cloudinit/make-seed.sh scratch http://192.168.64.1:8000/ \
#          ~/.weave/bringup/repo/weave-archive-keyring.asc
#
# Two different keys, doing two different jobs. The archive key is what apt checks
# to trust the packages; the channel key is what the guest checks to decide whether
# the host may command it afterwards. Neither substitutes for the other.
#
# You name the VM, not its channel key. The key belongs to the VM — weave mints it
# at create or clone — so asking an operator to locate and pass it would be asking
# them to hand-carry a credential the tooling already knows where to find, with a
# wrong path silently producing a guest that refuses every command.
#
# Attach it with: weave run <vm> --mount seed.iso
#
# Declarative, not screen automation: the guest is configured by a file it reads
# at boot, so the install is reproducible and reviewable rather than a sequence of
# keystrokes that has to hit the same pixels twice.
set -eu

VM="${1:-}"
REPO_URL="${2:-}"
KEY_FILE="${3:-}"
OUT="${4:-$HOME/.weave/bringup/seed.iso}"

# Where weave keeps its VMs. WEAVE_HOME overrides, matching the CLI.
CHANNEL_PUB="${WEAVE_HOME:-$HOME/.weave}/vms/$VM/channel.pub"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

if [ -z "$VM" ] || [ -z "$REPO_URL" ] || [ -z "$KEY_FILE" ]; then
	echo "usage: $0 <vm> <repo-url> <archive-key> [out.iso]" >&2
	exit 2
fi
[ -f "$KEY_FILE" ] || { echo "no such archive key: $KEY_FILE" >&2; exit 1; }
# Required, not optional. A seed that quietly omitted the channel key would build a
# guest that looks healthy and refuses every command — a much worse afternoon than
# a seed that refuses to build.
if [ ! -f "$CHANNEL_PUB" ]; then
	echo "VM \"$VM\" has no channel key at $CHANNEL_PUB" >&2
	echo "  weave mints one at create and clone; \`weave run $VM\` backfills an older VM." >&2
	exit 1
fi

SEED="$(dirname "$OUT")/seed"
rm -rf "$SEED"
mkdir -p "$SEED"

# A FRESH instance-id every build. cloud-init records the id it last ran for and
# treats a repeat as a resumed boot, skipping every module — the guest then boots
# clean with nothing installed and nothing in the log to say why. This one line
# is the difference between a seed that works twice and a seed that works once.
INSTANCE_ID="weave-bringup-$(uuidgen)"

cat > "$SEED/meta-data" <<EOF
instance-id: $INSTANCE_ID
local-hostname: weave-guest
EOF

# Splice the armored key in at the @@KEY@@ line, indented to sit under
# write_files' `content: |`. Split-and-cat rather than a substitution: an armored
# key is multi-line, and both sed's `s` and awk's -v choke on a replacement
# containing newlines — quietly, in awk's case, which would produce a seed that
# builds and then trusts nothing.
{
	sed -n '1,/^@@KEY@@$/p' "$HERE/user-data.tmpl" | sed '$d'
	sed 's/^/      /' "$KEY_FILE"
	sed -n '/^@@KEY@@$/,/^@@CHANNELKEY@@$/p' "$HERE/user-data.tmpl" | sed '1d;$d'
	sed 's/^/      /' "$CHANNEL_PUB"
	sed -n '/^@@CHANNELKEY@@$/,$p' "$HERE/user-data.tmpl" | sed '1d'
} > "$SEED/user-data"

# The URL is single-line, so a substitution is fine; | as the delimiter because
# the value contains slashes.
sed -i '' "s|@@REPO_URL@@|$REPO_URL|g" "$SEED/user-data"

rm -f "$OUT"
# The volume label MUST be CIDATA: the NoCloud datasource finds its seed by
# filesystem label, not by device, so a mislabelled ISO is simply never read.
hdiutil makehybrid -iso -joliet -default-volume-name CIDATA -o "$OUT" "$SEED" >/dev/null

echo "$OUT"
echo "  instance-id: $INSTANCE_ID"
echo "  repo:        $REPO_URL"
echo "  vm:          $VM"
echo "  channel key: $CHANNEL_PUB"
