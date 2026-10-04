#!/bin/sh
# Build the weave-agent installer package for macOS.
#
#   packaging/darwin/build-pkg.sh VERSION BIN_DIR OUT_DIR [ARCH]
#
# BIN_DIR holds weaveboot, weave-agent, weavectl and weavemanifest built for
# darwin/ARCH (default arm64). Writes OUT_DIR/weave-agent_VERSION_darwin_ARCH.pkg.
# With WEAVE_PKG_SIGN_IDENTITY set (a "Developer ID Installer: ..." identity in
# the keychain) the package is signed; without it, it is unsigned, and
# installs with `installer -pkg ... -target /` (docs/macos-package.md).
set -eu

if [ $# -lt 3 ]; then
	echo "usage: $0 VERSION BIN_DIR OUT_DIR [ARCH]" >&2
	exit 2
fi
version=$1
bindir=$2
out=$3
arch=${4:-arm64}
here=$(cd "$(dirname "$0")" && pwd)
pkg="$out/weave-agent_${version}_darwin_${arch}.pkg"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
scripts=$work/scripts

# Every directory in the payload is created at exactly the mode the system
# already has it at, root:wheel (--ownership recommended): installer applies a
# payload directory's mode to an existing one, and the payload root is "/".
# mktemp's 0700 would otherwise reach / itself.
mkdir -p "$root" "$scripts"
chmod 0755 "$root"
install -d -m 0755 "$root/usr" "$root/usr/local" "$root/usr/local/bin" \
	"$root/usr/local/libexec" "$root/usr/local/libexec/weave" \
	"$root/usr/local/libexec/weave/modules" \
	"$root/Library" "$root/Library/LaunchDaemons"

# All four binaries side by side: weaveboot runs core as "the binary beside
# me" until it has staged a core of its own.
for b in weaveboot weave-agent weavectl weavemanifest; do
	install -m 0755 "$bindir/$b" "$root/usr/local/libexec/weave/$b"
done
install -m 0755 "$here/uninstall.sh" "$root/usr/local/libexec/weave/uninstall.sh"
ln -s ../libexec/weave/weavectl "$root/usr/local/bin/weavectl"
install -m 0644 "$here/run.weaveplatform.agent.plist" "$root/Library/LaunchDaemons/run.weaveplatform.agent.plist"

for s in preinstall postinstall; do
	sed "s/@ARCH@/$arch/g" "$here/scripts/$s" >"$scripts/$s"
	chmod 0755 "$scripts/$s"
done

# Extended attributes would travel as AppleDouble ._* files beside every
# payload file (com.apple.provenance and quarantine, on a developer's Mac).
# COPYFILE_DISABLE keeps pkgbuild from writing them; clearing them is belt and
# braces where an attribute is not removable.
xattr -rc "$root" 2>/dev/null || true
export COPYFILE_DISABLE=1

mkdir -p "$out"
set -- --root "$root" --scripts "$scripts" \
	--identifier run.weaveplatform.agent --version "$version" \
	--install-location / --ownership recommended
if [ -n "${WEAVE_PKG_SIGN_IDENTITY:-}" ]; then
	set -- "$@" --sign "$WEAVE_PKG_SIGN_IDENTITY"
fi
pkgbuild "$@" "$pkg"
echo "$pkg"
