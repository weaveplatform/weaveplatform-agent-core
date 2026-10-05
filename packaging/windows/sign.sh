#!/bin/sh
# Authenticode signing for core's Windows artefacts, with osslsigncode.
#
#   packaging/windows/sign.sh setup
#   packaging/windows/sign.sh binary TARGET PATH
#   packaging/windows/sign.sh scripts OUT_DIR
#   packaging/windows/sign.sh file PATH...
#   packaging/windows/sign.sh verify PATH...
#   packaging/windows/sign.sh cleanup
#
# setup    writes the PFX (WINDOWS_CODESIGN_PFX, base64) and its password
#          (WINDOWS_CODESIGN_PFX_PASSWORD) to a private directory, and checks
#          the certificate in it is the one the Windows zip ships
#          (packaging/windows/weave-codesign.crt) and has the thumbprint
#          WINDOWS_CODESIGN_THUMBPRINT — and, when WINDOWS_CODESIGN_CERT
#          (base64 PEM) is set, is that certificate too. Anything else is a misconfigured
#          secret, and signing with it would ship binaries no guest trusts.
# binary   signs one binary: goreleaser's post-build hook, with TARGET its
#          {{ .Target }}. Not windows: nothing to do. No PFX: unsigned (a
#          local snapshot), unless WEAVE_WINDOWS_SIGN_REQUIRED=1, when it
#          fails. It verifies what it signed.
# scripts  stages what the Windows zip carries beside the binaries —
#          install.ps1, uninstall.ps1 and weave-codesign.crt — in OUT_DIR,
#          with the scripts signed and verified: goreleaser's before hook.
#          The copies, not the tracked files, are signed, so the work tree
#          stays clean for goreleaser. No PFX: as for binary.
# file     signs files in place: PE binaries and PowerShell scripts.
# verify   checks each file's signature chains to weave-codesign.crt alone,
#          and that its signing certificate has the pinned thumbprint.
# cleanup  deletes the PFX and the password. Run it always.
#
# Every signature is SHA-256 with an RFC 3161 timestamp, so it outlives the
# certificate: a module signed today still verifies after the certificate
# expires. The timestamp authorities are tried in turn, each with a few
# attempts, because a release must not fail on one TSA's bad minute.
# WEAVE_SIGN_DIR (default $RUNNER_TEMP/weave-sign-windows) holds the secrets;
# nothing secret is echoed or put on a command line.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=${WEAVE_SIGN_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/weave-sign-windows}
pfx=$dir/codesign.pfx
pass=$dir/codesign.pass
# WEAVE_CODESIGN_CERT stands in for the shipped certificate in sign_test.sh.
cert=${WEAVE_CODESIGN_CERT:-$here/weave-codesign.crt}
tsas=${WEAVE_TSA_URLS:-"http://timestamp.digicert.com http://timestamp.sectigo.com http://timestamp.globalsign.com/tsa/r6advanced1"}

die() {
	echo "sign.sh: $*" >&2
	exit 1
}

# sha1_of PEM_FILE: the certificate's SHA-1 thumbprint, 40 upper-case hex.
sha1_of() {
	openssl x509 -in "$1" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' | tr 'a-f' 'A-F'
}

thumbprint() {
	[ -n "${WINDOWS_CODESIGN_THUMBPRINT:-}" ] || die "WINDOWS_CODESIGN_THUMBPRINT is not set"
	printf '%s' "$WINDOWS_CODESIGN_THUMBPRINT" | tr 'a-f' 'A-F'
}

setup_failed() {
	rm -rf "$dir"
	die "$@"
}

setup() {
	[ -n "${WINDOWS_CODESIGN_PFX:-}" ] || die "WINDOWS_CODESIGN_PFX is not set"
	[ -n "${WINDOWS_CODESIGN_PFX_PASSWORD:-}" ] || die "WINDOWS_CODESIGN_PFX_PASSWORD is not set"
	want=$(thumbprint)
	command -v osslsigncode >/dev/null || die "osslsigncode is not installed"
	mkdir -p "$dir"
	chmod 700 "$dir"
	umask 077
	printf '%s' "$WINDOWS_CODESIGN_PFX" | base64 -d >"$pfx" 2>/dev/null ||
		printf '%s' "$WINDOWS_CODESIGN_PFX" | base64 -D >"$pfx"
	printf '%s' "$WINDOWS_CODESIGN_PFX_PASSWORD" >"$pass"
	# A secret that fails a check is not left behind for a later step to
	# sign with.
	openssl pkcs12 -in "$pfx" -passin "file:$pass" -nokeys -clcerts -out "$dir/leaf.pem" ||
		setup_failed "cannot read the certificate in WINDOWS_CODESIGN_PFX (wrong password?)"
	got=$(sha1_of "$dir/leaf.pem")
	[ "$got" = "$want" ] || setup_failed "the PFX certificate is $got, WINDOWS_CODESIGN_THUMBPRINT is $want"
	shipped=$(sha1_of "$cert")
	[ "$shipped" = "$want" ] ||
		setup_failed "packaging/windows/weave-codesign.crt is $shipped, WINDOWS_CODESIGN_THUMBPRINT is $want"
	if [ -n "${WINDOWS_CODESIGN_CERT:-}" ]; then
		printf '%s' "$WINDOWS_CODESIGN_CERT" | base64 -d >"$dir/var.pem" 2>/dev/null ||
			printf '%s' "$WINDOWS_CODESIGN_CERT" | base64 -D >"$dir/var.pem"
		var=$(sha1_of "$dir/var.pem")
		[ "$var" = "$want" ] || setup_failed "WINDOWS_CODESIGN_CERT is $var, WINDOWS_CODESIGN_THUMBPRINT is $want"
	fi
	echo "signing as $(openssl x509 -in "$dir/leaf.pem" -noout -subject) ($got)"
}

# sign_one FILE: signs FILE in place, trying each TSA up to three times.
sign_one() {
	[ -f "$pfx" ] || die "no PFX at $pfx (run: sign.sh setup)"
	for tsa in $tsas; do
		n=1
		while [ "$n" -le 3 ]; do
			rm -f "$1.signed"
			if osslsigncode sign -pkcs12 "$pfx" -readpass "$pass" -h sha256 \
				-n "weaveplatform agent" -i "https://github.com/weaveplatform/weaveplatform-agent-core" \
				-ts "$tsa" -in "$1" -out "$1.signed" >/dev/null; then
				mv -f "$1.signed" "$1"
				echo "signed $1 (timestamp: $tsa)"
				return 0
			fi
			echo "::warning::signing $1 with timestamp $tsa failed (attempt $n)" >&2
			sleep $((n * 5))
			n=$((n + 1))
		done
	done
	rm -f "$1.signed"
	die "could not sign $1 with any timestamp authority"
}

verify_one() {
	want=$(thumbprint)
	tsa_ca=${WEAVE_TSA_CAFILE:-/etc/ssl/cert.pem}
	[ -f "$tsa_ca" ] || tsa_ca=/etc/ssl/certs/ca-certificates.crt
	out=$(osslsigncode verify -in "$1" -CAfile "$cert" -TSA-CAfile "$tsa_ca" 2>&1) || {
		printf '%s\n' "$out" >&2
		die "$1: signature does not verify against weave-codesign.crt"
	}
	tmp=$(mktemp -d)
	osslsigncode extract-signature -pem -in "$1" -out "$tmp/sig.pem" >/dev/null
	openssl pkcs7 -in "$tmp/sig.pem" -print_certs -out "$tmp/certs.pem"
	n=$(grep -c 'BEGIN CERTIFICATE' "$tmp/certs.pem")
	got=$(sha1_of "$tmp/certs.pem")
	rm -rf "$tmp"
	[ "$n" -eq 1 ] || die "$1: the signature carries $n certificates, want only the signing one"
	[ "$got" = "$want" ] || die "$1: signed by $got, want $want"
	case $out in
	*"Timestamp Server Signature verification: ok"*) ;;
	*) die "$1: no verified RFC 3161 timestamp" ;;
	esac
	echo "verified $1: signed by $got, timestamped"
}

case ${1:-} in
setup) setup ;;
binary)
	[ $# -eq 3 ] || die "usage: sign.sh binary TARGET PATH"
	case $2 in
	windows_*) ;;
	*) exit 0 ;;
	esac
	if [ ! -f "$pfx" ]; then
		[ "${WEAVE_WINDOWS_SIGN_REQUIRED:-}" != 1 ] || die "no PFX to sign $3 with (run: sign.sh setup)"
		echo "sign.sh: no PFX; $3 left unsigned"
		exit 0
	fi
	sign_one "$3"
	verify_one "$3"
	;;
scripts)
	[ $# -eq 2 ] || die "usage: sign.sh scripts OUT_DIR"
	mkdir -p "$2"
	cp "$here/install.ps1" "$here/uninstall.ps1" "$cert" "$2/"
	[ "$(basename "$cert")" = weave-codesign.crt ] || mv "$2/$(basename "$cert")" "$2/weave-codesign.crt"
	if [ ! -f "$pfx" ]; then
		[ "${WEAVE_WINDOWS_SIGN_REQUIRED:-}" != 1 ] || die "no PFX to sign the install scripts with (run: sign.sh setup)"
		echo "sign.sh: no PFX; the install scripts are left unsigned"
		exit 0
	fi
	for f in "$2/install.ps1" "$2/uninstall.ps1"; do
		sign_one "$f"
		verify_one "$f"
	done
	;;
file)
	shift
	for f in "$@"; do sign_one "$f"; done
	;;
verify)
	shift
	[ $# -gt 0 ] || die "usage: sign.sh verify PATH..."
	for f in "$@"; do verify_one "$f"; done
	;;
cleanup) rm -rf "$dir" ;;
*) die "usage: sign.sh setup|binary TARGET PATH|scripts OUT_DIR|file PATH...|verify PATH...|cleanup" ;;
esac
