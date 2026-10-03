//go:build !dev

package core

import _ "embed"

// embeddedRootPub is the manifest signing chain's root public key, baked
// into release builds so the trust anchor cannot be swapped by pointing
// core at a different file. It is empty until a real root key is
// provisioned into keys/root.pub, in which case channel installs stay
// disabled (fail closed) rather than trusting an operator-supplied key.
//
//go:embed keys/root.pub
var embeddedRootPub []byte

// allowRootPubOverride is false in release builds: the --manifest-root-pub
// flag / WEAVE_MANIFEST_ROOT_PUB env is ignored so the anchor is fixed.
const allowRootPubOverride = false
