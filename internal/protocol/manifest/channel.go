package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// ErrInvalidChannel is wrapped by every structural refusal ParseChannel
// reports; the message after it names what is wrong.
var ErrInvalidChannel = errors.New("channel manifest")

// ChannelManifest is the signed document mapping a channel to a known-good
// set of core and module versions and the protocol they assume
// (schema/channel-manifest.schema.json). SaaS follows a rolling manifest;
// self-hosted pins one. Same mechanism, different policy.
type ChannelManifest struct {
	Schema      int    `json:"schema"`
	Channel     string `json:"channel"`
	GeneratedAt string `json:"generated_at"` //nolint:tagliatelle // channel manifest file format (schema/channel-manifest.schema.json)
	// Sequence is a monotonic counter per channel. Core persists the
	// highest sequence it has accepted and refuses any manifest with a
	// lower one — the anti-rollback defence a bare signature lacks.
	Sequence uint64 `json:"sequence"`
	// Expires bounds freshness (RFC3339). Core refuses an expired
	// manifest, defeating a freeze attack (serving a stale-but-signed
	// document forever). Empty means no expiry (dev/self-hosted pins).
	Expires  string            `json:"expires,omitempty"`
	Protocol ProtocolWindow    `json:"protocol"`
	Bindings map[string]string `json:"bindings,omitempty"`
	Core     ChannelCore       `json:"core"`
	Modules  []ChannelModule   `json:"modules"`
	// Images lists promoted weave guest images (weaveplatform-oci artifact
	// contract v1). Core does not consume it; hostweave and the guestweave
	// CLIs admit only index digests a verified channel lists.
	Images []ChannelImage `json:"images,omitempty"`
}

// ChannelImage is one promoted guest image. Repository is the path without
// a registry host, so one entry admits the image whether it is pulled from
// GHCR, a site mirror or an air-gapped OCI layout.
type ChannelImage struct {
	Repository string                 `json:"repository"`
	Tag        string                 `json:"tag"`
	Digest     string                 `json:"digest"`
	Platforms  []ChannelImagePlatform `json:"platforms,omitempty"`
	Signature  *ChannelImageSigner    `json:"signature,omitempty"`
	BuildDate  string                 `json:"build_date,omitempty"` //nolint:tagliatelle // channel manifest file format (schema/channel-manifest.schema.json)
}

// ChannelImagePlatform is one child manifest of an image index.
type ChannelImagePlatform struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	OSVersion string `json:"os_version,omitempty"` //nolint:tagliatelle // channel manifest file format (schema/channel-manifest.schema.json)
	Digest    string `json:"digest"`
}

// ChannelImageSigner names the build-time signature consumers should also
// expect: a cosign key (by its hint) or a GitHub attestation identity.
type ChannelImageSigner struct {
	Provider      string `json:"provider"`
	KeyID         string `json:"key_id,omitempty"` //nolint:tagliatelle // channel manifest file format (schema/channel-manifest.schema.json)
	Issuer        string `json:"issuer,omitempty"`
	SubjectRegexp string `json:"subject_regexp,omitempty"` //nolint:tagliatelle // channel manifest file format (schema/channel-manifest.schema.json)
}

// Image returns the entry promoting index digest in repository; an empty
// repository matches any.
func (c *ChannelManifest) Image(repository, digest string) (*ChannelImage, bool) {
	for i := range c.Images {
		if c.Images[i].Digest == digest &&
			(repository == "" || c.Images[i].Repository == repository) {
			return &c.Images[i], true
		}
	}
	return nil, false
}

// Expired reports whether the manifest's Expires time is in the past.
// now is passed in so callers control the clock (and tests are
// deterministic). A manifest with no Expires never expires.
func (c *ChannelManifest) Expired(now time.Time) bool {
	if c.Expires == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, c.Expires)
	if err != nil {
		return true // unparseable expiry is treated as expired: fail closed.
	}
	return now.After(exp)
}

// ProtocolWindow is the accepted protocol range the channel assumes.
type ProtocolWindow struct {
	Min uint32 `json:"min"`
	Max uint32 `json:"max"`
}

// ChannelCore describes the core release the channel serves.
type ChannelCore struct {
	Version   string            `json:"version"`
	Artifacts []ChannelArtifact `json:"artifacts"`
}

// ChannelModule is the distribution subset of a module's manifest: enough
// signed data for core to gate fetch and exec decisions before it
// possesses the binary.
type ChannelModule struct {
	ID           string            `json:"id"`
	Version      string            `json:"version"`
	Protocol     uint32            `json:"protocol"`
	Privilege    string            `json:"privilege"`
	Session      string            `json:"session"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Subscribes   []string          `json:"subscribes,omitempty"`
	Signing      *Signing          `json:"signing,omitempty"`
	Artifacts    []ChannelArtifact `json:"artifacts"`
}

// ChannelArtifact is one downloadable binary.
type ChannelArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// ParseChannel unmarshals and validates a channel manifest.
func ParseChannel(data []byte) (*ChannelManifest, error) {
	var c ChannelManifest
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("channel manifest: %w", err)
	}
	if c.Schema != 1 {
		return nil, fmt.Errorf("%w: unsupported schema %d", ErrInvalidChannel, c.Schema)
	}
	if c.Channel == "" || c.Protocol.Min == 0 || c.Protocol.Max < c.Protocol.Min {
		return nil, fmt.Errorf("%w: missing channel or invalid protocol window", ErrInvalidChannel)
	}
	// Validate every module id/version before any of them are used to build
	// filesystem paths downstream (staging/<id>/<version>, os.RemoveAll,
	// os.Rename as root). A signed manifest with id "../../etc" must be
	// rejected here, not caught by luck later.
	for i := range c.Modules {
		if !idRe.MatchString(c.Modules[i].ID) {
			return nil, fmt.Errorf("%w: invalid module id %q", ErrInvalidChannel, c.Modules[i].ID)
		}
		if !versionRe.MatchString(c.Modules[i].Version) {
			return nil, fmt.Errorf(
				"%w: invalid version %q for module %q",
				ErrInvalidChannel,
				c.Modules[i].Version,
				c.Modules[i].ID,
			)
		}
	}
	// An image digest is the identity a consumer pins; one that is not a
	// well-formed sha256 digest can never match a pull and is refused rather
	// than silently admitting nothing.
	for i := range c.Images {
		img := &c.Images[i]
		if img.Repository == "" || img.Tag == "" || !digestRe.MatchString(img.Digest) {
			return nil, fmt.Errorf(
				"%w: invalid image entry %q:%q %q",
				ErrInvalidChannel,
				img.Repository,
				img.Tag,
				img.Digest,
			)
		}
		for _, p := range img.Platforms {
			if !digestRe.MatchString(p.Digest) {
				return nil, fmt.Errorf(
					"%w: invalid platform digest %q for image %q",
					ErrInvalidChannel,
					p.Digest,
					img.Repository,
				)
			}
		}
	}
	return &c, nil
}

// Module returns the named module's entry.
func (c *ChannelManifest) Module(id string) (*ChannelModule, bool) {
	for i := range c.Modules {
		if c.Modules[i].ID == id {
			return &c.Modules[i], true
		}
	}
	return nil, false
}

// ArtifactForHost picks the artifact matching this process's OS/arch.
func ArtifactForHost(arts []ChannelArtifact) (*ChannelArtifact, bool) {
	for i := range arts {
		if arts[i].OS == runtime.GOOS && arts[i].Arch == runtime.GOARCH {
			return &arts[i], true
		}
	}
	return nil, false
}

// ModuleManifest converts the distribution subset back into the manifest
// core's supervisor consumes.
func (cm *ChannelModule) ModuleManifest(platforms []Platform) *Manifest {
	return &Manifest{
		Schema:       1,
		ID:           cm.ID,
		Version:      cm.Version,
		Protocol:     cm.Protocol,
		Zone:         "A",
		Privilege:    cm.Privilege,
		Session:      cm.Session,
		Platforms:    platforms,
		Capabilities: cm.Capabilities,
		Subscribes:   cm.Subscribes,
		Signing:      cm.Signing,
	}
}
