package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/manifestverify"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Refusals from the channel verifier. Each is the fixed part of its message, so
// a caller can test for the reason with errors.Is.
var (
	errNoManifest       = errors.New("no manifest accompanies")
	errNotInChannel     = errors.New("not in the signed channel manifest")
	errVersionMismatch  = errors.New("on disk is a version the channel does not sign")
	errNoArtifact       = errors.New("the channel signs no artifact for this platform")
	errPrivilegeGrant   = errors.New("asks for a privilege the channel does not grant")
	errSessionGrant     = errors.New("asks for a session the channel does not grant")
	errProtocolMismatch = errors.New("declares a protocol the channel does not sign")
	errCapabilityGrant  = errors.New("requires a capability the channel does not grant")
	errDigestMismatch   = errors.New("does not match the channel's digest")
	errNoRootKey        = errors.New("a channel directory needs a root public key to anchor it")
	errNotRootKey       = errors.New("not the root key")
)

// NewChannel authenticates module binaries against a signed channel manifest:
// the root key endorses a signing key, the signing key signs the manifest, and
// the manifest names each artifact's SHA-256.
//
// This is the verification story for platforms with no OS-level signature to
// check — Linux has no equivalent of codesign or Authenticode — and it works
// offline, which is what a guest needs. The bundle is verified once here rather
// than per module: a manifest that does not chain to the root is a startup
// failure, not something to rediscover on each exec.
//
// # Why the module's own manifest cannot be the source of truth
//
// core.discoverModules loads module.manifest.json from the SAME directory as
// the binary, so anything able to replace the binary can rewrite the manifest
// beside it. Checking a binary against a digest in that file would be circular
// and would authenticate nothing.
//
// The same reasoning extends past the digest. That on-disk manifest also
// declares privilege, session and protocol — which core uses to decide whether
// to run a module as root and in whose session. Those are cross-checked against
// the signed entry too, so an attacker who rewrites the manifest to ask for more
// privilege is refused rather than obeyed.
func NewChannel(
	log *slog.Logger,
	rootPub ed25519.PublicKey,
	bundle manifestverify.Bundle,
) (supervise.Verifier, error) {
	channel, err := manifestverify.Verify(rootPub, bundle)
	if err != nil {
		return nil, fmt.Errorf("verify: channel manifest: %w", err)
	}
	if log != nil {
		log.Info("module verification anchored to the signed channel manifest",
			"channel", channel.Channel, "modules", len(channel.Modules))
	}

	signed := make(map[string]manifest.ChannelModule, len(channel.Modules))
	for _, m := range channel.Modules {
		signed[m.ID] = m
	}

	return supervise.VerifierFunc(func(path string, onDisk *manifest.Manifest) error {
		if onDisk == nil {
			return fmt.Errorf("verify: %w %s", errNoManifest, path)
		}
		entry, ok := signed[onDisk.ID]
		if !ok {
			return fmt.Errorf("verify: module %q is %w", onDisk.ID, errNotInChannel)
		}
		if entry.Version != onDisk.Version {
			return fmt.Errorf("verify: module %s on disk is version %s, the channel signs %s: %w",
				onDisk.ID, onDisk.Version, entry.Version, errVersionMismatch)
		}
		if err := matchesSignedGrants(onDisk, entry); err != nil {
			return err
		}

		artifact, ok := artifactFor(entry, runtime.GOOS, runtime.GOARCH)
		if !ok {
			return fmt.Errorf("verify: the channel signs no %s/%s artifact for module %s: %w",
				runtime.GOOS, runtime.GOARCH, onDisk.ID, errNoArtifact)
		}
		return digestMatches(path, artifact.Digest)
	}), nil
}

// matchesSignedGrants refuses a module whose on-disk manifest claims more than
// the signed entry grants. These four fields decide how much authority core
// hands the module, so a mismatch is tampering, not drift.
func matchesSignedGrants(onDisk *manifest.Manifest, entry manifest.ChannelModule) error {
	if onDisk.Privilege != entry.Privilege {
		return fmt.Errorf("verify: module %s asks for privilege %q, the channel grants %q: %w",
			onDisk.ID, onDisk.Privilege, entry.Privilege, errPrivilegeGrant)
	}
	if onDisk.Session != entry.Session {
		return fmt.Errorf("verify: module %s asks for session %q, the channel grants %q: %w",
			onDisk.ID, onDisk.Session, entry.Session, errSessionGrant)
	}
	if onDisk.Protocol != entry.Protocol {
		return fmt.Errorf("verify: module %s declares protocol %d, the channel signs %d: %w",
			onDisk.ID, onDisk.Protocol, entry.Protocol, errProtocolMismatch)
	}
	if extra := notGranted(onDisk.Capabilities, entry.Capabilities); extra != "" {
		return fmt.Errorf("verify: module %s requires capability %q: %w",
			onDisk.ID, extra, errCapabilityGrant)
	}
	return nil
}

// notGranted returns the first element of want the channel did not sign.
func notGranted(want, granted []string) string {
	for _, w := range want {
		if !slices.Contains(granted, w) {
			return w
		}
	}
	return ""
}

func artifactFor(
	entry manifest.ChannelModule,
	goos, goarch string,
) (manifest.ChannelArtifact, bool) {
	for _, a := range entry.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return manifest.ChannelArtifact{}, false
}

// digestMatches hashes the binary and compares it to the signed digest.
func digestMatches(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("verify: opening %s: %w", path, err)
	}
	defer f.Close()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return fmt.Errorf("verify: hashing %s: %w", path, err)
	}
	got := "sha256:" + hex.EncodeToString(sum.Sum(nil))
	if got != want {
		return fmt.Errorf(
			"verify: %s is %s, the channel signs %s: %w",
			path,
			got,
			want,
			errDigestMismatch,
		)
	}
	return nil
}

// Bundle file names inside a channel directory. They mirror what
// `weavemanifest sign` emits, so an operator can drop that output in place.
const (
	channelManifestFile = "channel.json"
	channelSigFile      = "channel.json.sig"
	signingKeyFile      = "signing.pub"
	signingKeySigFile   = "signing.pub.sig"
)

// NewChannelFromDir loads a signed channel bundle from disk and anchors module
// verification to it.
//
// This is the offline path: a VM guest or an air-gapped host has no manifest
// server to fetch from, so the bundle ships beside the modules. rootPubPath is
// the trust anchor and must come from somewhere the module directory cannot
// reach — packaged with core, not written next to what it authenticates.
func NewChannelFromDir(log *slog.Logger, rootPubPath, dir string) (supervise.Verifier, error) {
	if rootPubPath == "" {
		return nil, fmt.Errorf("verify: %w", errNoRootKey)
	}
	rootBytes, err := os.ReadFile(rootPubPath)
	if err != nil {
		return nil, fmt.Errorf("verify: reading the root public key: %w", err)
	}
	rootKey, rootRaw, err := manifest.ParsePublicKey(rootBytes)
	if err != nil {
		return nil, fmt.Errorf("verify: root public key: %w", err)
	}
	if rootKey.KeyID != "root" {
		return nil, fmt.Errorf(
			"verify: %s holds key %q, %w",
			rootPubPath,
			rootKey.KeyID,
			errNotRootKey,
		)
	}

	var bundle manifestverify.Bundle
	for _, part := range []struct {
		name string
		dst  *[]byte
	}{
		{channelManifestFile, &bundle.Manifest},
		{channelSigFile, &bundle.ManifestSig},
		{signingKeyFile, &bundle.SigningKey},
		{signingKeySigFile, &bundle.SigningKeySig},
	} {
		b, err := os.ReadFile(filepath.Join(dir, part.name))
		if err != nil {
			return nil, fmt.Errorf("verify: channel bundle: %w", err)
		}
		*part.dst = b
	}
	return NewChannel(log, ed25519.PublicKey(rootRaw), bundle)
}
