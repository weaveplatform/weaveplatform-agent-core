#!/bin/sh
# Developer ID signing and notarisation for core's macOS artefacts.
#
#   packaging/darwin/sign.sh keychain
#   packaging/darwin/sign.sh binary TARGET PATH
#   packaging/darwin/sign.sh binaries DIR
#   packaging/darwin/sign.sh verify-binaries DIR
#   packaging/darwin/sign.sh package VERSION BIN_DIR OUT_DIR [ARCH]
#   packaging/darwin/sign.sh verify-package PKG
#   packaging/darwin/sign.sh cleanup
#
# keychain   makes a throwaway keychain with a random password and imports the
#            Developer ID identities whose secrets are set:
#              APPLE_DEVELOPER_ID_APP_P12, APPLE_DEVELOPER_ID_APP_P12_PASSWORD
#              APPLE_DEVELOPER_ID_INSTALLER_P12, APPLE_DEVELOPER_ID_INSTALLER_P12_PASSWORD
#            (each .p12 base64). Every later command finds its identity in that
#            keychain by kind and team, never by a hard-coded name.
# binary     signs one binary: goreleaser's post-build hook, with TARGET its
#            {{ .Target }}. Not darwin: nothing to do. No keychain: unsigned
#            (a local snapshot), unless WEAVE_SIGN_REQUIRED=1, when it fails.
# binaries   signs weaveboot, weave-agent, weavectl and weavemanifest in DIR.
# package    checks DIR's binaries carry the team's signature, builds the .pkg
#            from exactly those (build-pkg.sh) signed with the Installer
#            identity, notarises it, staples the ticket and verifies the result.
#            Needs APPLE_NOTARY_KEY_P8 (base64), APPLE_NOTARY_KEY_ID and
#            APPLE_NOTARY_ISSUER_ID.
# cleanup    deletes the keychain and the notary key. Run it always.
#
# APPLE_TEAM_ID (required) is the team every identity and signature must
# carry. WEAVE_SIGN_DIR (default $RUNNER_TEMP/weave-sign) holds the keychain
# and, only while notarytool runs, the .p8. Nothing secret is echoed; under
# GitHub Actions the keychain password is masked as well.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=${WEAVE_SIGN_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/weave-sign}
kc=$dir/signing.keychain-db
p8=$dir/notary.p8
binaries="weaveboot weave-agent weavectl weavemanifest"

die() {
	echo "sign.sh: $*" >&2
	exit 1
}

team() {
	[ -n "${APPLE_TEAM_ID:-}" ] || die "APPLE_TEAM_ID is not set"
	printf '%s' "$APPLE_TEAM_ID"
}

# identity KIND: the one "Developer ID KIND: <name> (TEAM)" identity in the
# keychain, by name. Zero or several is an error: either would sign with the
# wrong thing.
identity() {
	t=$(team)
	[ -f "$kc" ] || die "no signing keychain at $kc (run: sign.sh keychain)"
	ids=$(security find-identity -v "$kc" |
		sed -n "s/^ *[0-9][0-9]*) [0-9A-F]\{40\} \"\(Developer ID $1: .* ($t)\)\"\$/\1/p" | sort -u)
	n=$(printf '%s' "$ids" | grep -c . || true)
	[ "$n" -eq 1 ] || die "want exactly one 'Developer ID $1: … ($t)' identity in the keychain, found $n"
	printf '%s' "$ids"
}

import_p12() { # import_p12 VAR PASSWORD_VAR: the base64 .p12 in $VAR
	b64=$(printenv "$1" || true)
	pw=$(printenv "$2" || true)
	f=$dir/$1.p12
	printf '%s' "$b64" | base64 --decode >"$f" || die "$1 is not base64"
	security import "$f" -k "$kc" -f pkcs12 -P "$pw" \
		-T /usr/bin/codesign -T /usr/bin/pkgbuild -T /usr/bin/productbuild -T /usr/bin/productsign >/dev/null ||
		{ rm -f "$f"; die "could not import $1"; }
	rm -f "$f"
	echo "imported $1"
}

cmd_keychain() {
	team >/dev/null
	umask 077
	mkdir -p "$dir"
	[ ! -e "$kc" ] || die "a signing keychain already exists at $kc (run: sign.sh cleanup)"
	pw=$(openssl rand -hex 32)
	if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$pw"; fi
	security create-keychain -p "$pw" "$kc"
	# Unlocked for six hours, and never by sleep, for the length of a job.
	security set-keychain-settings -t 21600 "$kc"
	security unlock-keychain -p "$pw" "$kc"
	[ -n "${APPLE_DEVELOPER_ID_APP_P12:-}${APPLE_DEVELOPER_ID_INSTALLER_P12:-}" ] ||
		die "neither APPLE_DEVELOPER_ID_APP_P12 nor APPLE_DEVELOPER_ID_INSTALLER_P12 is set"
	if [ -n "${APPLE_DEVELOPER_ID_APP_P12:-}" ]; then
		import_p12 APPLE_DEVELOPER_ID_APP_P12 APPLE_DEVELOPER_ID_APP_P12_PASSWORD
	fi
	if [ -n "${APPLE_DEVELOPER_ID_INSTALLER_P12:-}" ]; then
		import_p12 APPLE_DEVELOPER_ID_INSTALLER_P12 APPLE_DEVELOPER_ID_INSTALLER_P12_PASSWORD
	fi
	# Lets codesign and the installer tools use the keys without a prompt.
	security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$pw" "$kc" >/dev/null
	# On the search list, ahead of the user's own, for pkgbuild and stapler.
	# shellcheck disable=SC2046 # the existing list is one path per word
	security list-keychains -d user -s "$kc" $(security list-keychains -d user | tr -d '"')
	echo "identities:"
	security find-identity -v "$kc" | sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(.*\)"$/  \1/p' | sort -u
}

cmd_binary() { # cmd_binary TARGET PATH
	case $1 in darwin_*) ;; *) return 0 ;; esac
	if [ ! -f "$kc" ]; then
		[ "${WEAVE_SIGN_REQUIRED:-}" != 1 ] || die "$2: no signing keychain, and signing is required"
		echo "sign.sh: $2 left unsigned (no signing keychain)"
		return 0
	fi
	id=$(identity Application)
	name=$(basename "$2")
	codesign --force --sign "$id" --keychain "$kc" --identifier "run.weaveplatform.$name" \
		--options runtime --timestamp "$2"
	verify_binary "$2"
}

verify_binary() {
	t=$(team)
	codesign --verify --strict --deep --verbose=2 "$1"
	got=$(codesign -dv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p')
	[ "$got" = "$t" ] || die "$1: TeamIdentifier=$got, want $t"
	codesign -dv "$1" 2>&1 | grep -E '^(Identifier|Authority|Timestamp|TeamIdentifier|CodeDirectory)' | sed "s|^|  $(basename "$1"): |"
	# Hardened runtime and a secure timestamp: notarisation refuses either missing.
	codesign -dv "$1" 2>&1 | grep -q 'flags=.*runtime' || die "$1: no hardened runtime"
	codesign -dv "$1" 2>&1 | grep -q '^Timestamp=' || die "$1: no secure timestamp"
}

cmd_binaries() {
	for b in $binaries; do cmd_binary darwin_ "$1/$b"; done
}

cmd_verify_binaries() {
	for b in $binaries; do verify_binary "$1/$b"; done
}

notary() { # notary SUBCOMMAND ARGS...: notarytool with the API key
	xcrun notarytool "$@" --key "$p8" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID"
}

cmd_package() { # cmd_package VERSION BIN_DIR OUT_DIR [ARCH]
	version=$1 bindir=$2 out=$3 arch=${4:-arm64}
	for v in APPLE_NOTARY_KEY_P8 APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID; do
		[ -n "$(printenv "$v" || true)" ] || die "$v is not set"
	done
	# What goes in is what was signed: refuse a binary without the team's signature.
	cmd_verify_binaries "$bindir"

	pkg=$out/weave-agent_${version}_darwin_${arch}.pkg
	installer=$(identity Installer)
	WEAVE_PKG_SIGN_IDENTITY=$installer WEAVE_PKG_SIGN_KEYCHAIN=$kc \
		sh "$here/build-pkg.sh" "$version" "$bindir" "$out" "$arch" >/dev/null

	umask 077
	mkdir -p "$dir"
	trap 'rm -f "$p8"' EXIT INT TERM
	printf '%s' "$APPLE_NOTARY_KEY_P8" | base64 --decode >"$p8" || die "APPLE_NOTARY_KEY_P8 is not base64"
	result=$dir/notary-submit.json
	notary submit "$pkg" --wait --timeout 45m --output-format json >"$result" || true
	id=$(plutil -extract id raw -o - "$result" 2>/dev/null || true)
	status=$(plutil -extract status raw -o - "$result" 2>/dev/null || true)
	echo "notarisation submission: ${id:-none} status: ${status:-unknown}"
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf 'submission-id=%s\nstatus=%s\n' "$id" "$status" >>"$GITHUB_OUTPUT"
	fi
	if [ "$status" != Accepted ]; then
		[ -z "$id" ] || notary log "$id" || true
		[ -n "$id" ] || cat "$result" >&2
		rm -f "$p8"
		die "notarisation of $pkg was not accepted"
	fi
	rm -f "$p8"

	xcrun stapler staple "$pkg"
	cmd_verify_package "$pkg"
	echo "$pkg"
}

cmd_verify_package() {
	t=$(team)
	pkgutil --check-signature "$1" | tee "$dir/check-signature.txt"
	grep -q "Developer ID Installer: .* ($t)" "$dir/check-signature.txt" ||
		die "$1: not signed by a Developer ID Installer identity of team $t"
	grep -q 'Status: signed by a developer certificate issued by Apple' "$dir/check-signature.txt" ||
		die "$1: signature does not chain to Apple"
	xcrun stapler validate "$1"
	spctl -a -vv -t install "$1" 2>&1 | tee "$dir/spctl.txt"
	grep -q 'accepted' "$dir/spctl.txt" || die "$1: Gatekeeper refuses it"
	grep -q 'source=Notarized Developer ID' "$dir/spctl.txt" || die "$1: Gatekeeper does not see it as notarised"
	# And the binaries inside it are the signed ones.
	x=$(mktemp -d)
	pkgutil --expand-full "$1" "$x/p" >/dev/null
	cmd_verify_binaries "$x/p/Payload/usr/local/libexec/weave"
	rm -rf "$x"
}

cmd_cleanup() {
	rm -f "$p8" "$dir"/*.p12
	if [ -f "$kc" ]; then
		security delete-keychain "$kc" || rm -f "$kc"
	fi
	rm -rf "$dir"
	echo "signing keychain and notary key removed"
}

[ $# -ge 1 ] || die "usage: sign.sh keychain|binary|binaries|verify-binaries|package|verify-package|cleanup ..."
c=$1
shift
case $c in
keychain) cmd_keychain ;;
binary) [ $# -eq 2 ] || die "usage: sign.sh binary TARGET PATH"; cmd_binary "$@" ;;
binaries) [ $# -eq 1 ] || die "usage: sign.sh binaries DIR"; cmd_binaries "$1" ;;
verify-binaries) [ $# -eq 1 ] || die "usage: sign.sh verify-binaries DIR"; cmd_verify_binaries "$1" ;;
package) [ $# -ge 3 ] || die "usage: sign.sh package VERSION BIN_DIR OUT_DIR [ARCH]"; cmd_package "$@" ;;
verify-package) [ $# -eq 1 ] || die "usage: sign.sh verify-package PKG"; cmd_verify_package "$1" ;;
cleanup) cmd_cleanup ;;
*) die "unknown command: $c" ;;
esac
