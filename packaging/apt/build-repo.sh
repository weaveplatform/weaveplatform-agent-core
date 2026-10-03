#!/bin/sh
# Build the weave-agent Debian package and the signed apt repository that
# serves it.
#
#   ./packaging/apt/build-repo.sh <gpg-key-id> [outdir]
#
# This is the local bring-up path: one command from a working tree to something a
# guest can `apt-get install weave-agent` from. The package is the one the release
# builds (goreleaser's nfpms), from a snapshot of this tree.
#
# Core ships no modules, so neither does this repository. A guest gets its
# modules from the channel, the same path a product guest uses; for local
# bring-up, weaveplatform-agent-modules builds module .debs of its own.
set -eu

KEY="${1:-}"
OUT="${2:-$HOME/.weave/bringup/repo}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
ARCH="${ARCH:-arm64}"
STAGE="$(dirname "$OUT")/debs"

if [ -z "$KEY" ]; then
	echo "usage: $0 <gpg-key-id> [outdir]" >&2
	echo "  the key signs Release, which is the only thing apt actually verifies" >&2
	exit 2
fi

# GOWORK=off throughout: a workspace masks stale go.mod pins, and a package
# built against workspace-resolved dependencies is not the package CI would build.
export GOWORK=off

echo "==> weave-agent"
cd "$HERE"
goreleaser release --snapshot --clean --skip=sign,archive,publish --timeout 15m >/dev/null

echo "==> repository"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$HERE/dist/weave-agent_"*"_$ARCH.deb" "$STAGE/"

go run ./packaging/apt/aptrepo -in "$STAGE" -out "$OUT" -key "$KEY"
go run ./packaging/apt/aptrepo -verify "$OUT"
