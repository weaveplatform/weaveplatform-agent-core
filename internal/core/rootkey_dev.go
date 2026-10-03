//go:build dev

package core

// Dev builds carry no embedded root key and DO honour the
// --manifest-root-pub override, so a developer can point core at a
// locally-generated signing chain (see weavemanifest keygen).
var embeddedRootPub []byte

const allowRootPubOverride = true
