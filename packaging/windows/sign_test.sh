#!/bin/sh
# Exercises sign.sh end to end with a throwaway certificate: what a release
# does with the real one, without its secrets. Needs osslsigncode, openssl
# and go, and reaches a public timestamp authority.
#
#   packaging/windows/sign_test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sign="$here/sign.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

cd "$work"
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes -keyout key.pem -out cert.pem \
	-subj "/CN=weave sign test/O=weave test" \
	-addext "basicConstraints=critical,CA:false" \
	-addext "keyUsage=critical,digitalSignature" \
	-addext "extendedKeyUsage=codeSigning" 2>/dev/null
openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.pfx -passout pass:test-password \
	-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256
thumb=$(openssl x509 -in cert.pem -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
(cd "$root" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOWORK=off go build -o "$work/weavectl.exe" ./cmd/weavectl)
cp "$here/install.ps1" install.ps1
cp weavectl.exe unsigned.exe

WEAVE_SIGN_DIR=$work/secrets
WEAVE_CODESIGN_CERT=$work/cert.pem
WINDOWS_CODESIGN_PFX=$(base64 <cert.pfx | tr -d '\n')
WINDOWS_CODESIGN_PFX_PASSWORD=test-password
export WEAVE_SIGN_DIR WEAVE_CODESIGN_CERT WINDOWS_CODESIGN_PFX WINDOWS_CODESIGN_PFX_PASSWORD

# Setup refuses a PFX whose certificate is not the pinned one.
if WINDOWS_CODESIGN_THUMBPRINT=0000000000000000000000000000000000000000 sh "$sign" setup 2>/dev/null; then
	fail "setup accepted a PFX that does not match the pinned thumbprint"
fi
export WINDOWS_CODESIGN_THUMBPRINT="$thumb"

# Setup refuses a WINDOWS_CODESIGN_CERT that is not the pinned one.
if WINDOWS_CODESIGN_THUMBPRINT=$thumb WINDOWS_CODESIGN_CERT=$(base64 <"$here/weave-codesign.crt" | tr -d '\n') \
	sh "$sign" setup 2>/dev/null; then
	fail "setup accepted a WINDOWS_CODESIGN_CERT that does not match"
fi

# No PFX yet: a snapshot leaves binaries unsigned, a release refuses.
sh "$sign" binary windows_amd64_v1 weavectl.exe | grep -q 'left unsigned' || fail "no PFX: not left unsigned"
sh "$sign" scripts unsigned-scripts | grep -q 'left unsigned' || fail "no PFX: scripts not left unsigned"
if WEAVE_WINDOWS_SIGN_REQUIRED=1 sh "$sign" binary windows_amd64_v1 weavectl.exe 2>/dev/null; then
	fail "no PFX with WEAVE_WINDOWS_SIGN_REQUIRED=1 did not fail"
fi

WINDOWS_CODESIGN_CERT=$(base64 <cert.pem | tr -d '\n') sh "$sign" setup
[ "$(stat -c %a "$WEAVE_SIGN_DIR" 2>/dev/null || stat -f %Lp "$WEAVE_SIGN_DIR")" = 700 ] ||
	fail "the secrets directory is not private"

# Not a Windows target: untouched.
sh "$sign" binary darwin_arm64_v8.0 weavectl.exe
cmp -s weavectl.exe unsigned.exe || fail "a non-Windows target was modified"

sh "$sign" binary windows_amd64_v1 weavectl.exe
sh "$sign" file install.ps1
sh "$sign" verify weavectl.exe install.ps1
tail -1 install.ps1 | grep -q 'SIG # End signature block' || fail "install.ps1 has no signature block"

# The zip's extras, staged and signed; the tracked scripts untouched.
sh "$sign" scripts staged
for f in install.ps1 uninstall.ps1 weave-codesign.crt; do
	[ -f "staged/$f" ] || fail "staged/$f missing"
done
sh "$sign" verify staged/install.ps1 staged/uninstall.ps1
cmp -s staged/weave-codesign.crt cert.pem || fail "staged a different certificate"
if tail -1 "$here/install.ps1" | grep -q 'SIG #'; then
	fail "the tracked install.ps1 was signed in place"
fi

if sh "$sign" verify unsigned.exe 2>/dev/null; then
	fail "an unsigned binary verified"
fi
if WINDOWS_CODESIGN_THUMBPRINT=0000000000000000000000000000000000000000 sh "$sign" verify weavectl.exe 2>/dev/null; then
	fail "a binary verified under another thumbprint"
fi

sh "$sign" cleanup
[ ! -e "$WEAVE_SIGN_DIR" ] || fail "cleanup left the secrets"
echo "sign.sh: ok"
