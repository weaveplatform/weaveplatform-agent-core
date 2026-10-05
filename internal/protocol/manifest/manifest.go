// Package manifest carries the Go types for the module manifest
// (schema/module-manifest.schema.json): the document every module authors,
// embeds, and publishes, and that core gates launch decisions on.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// ErrInvalidManifest is wrapped by every structural refusal Validate (and so
// Parse) reports; the message after it names what is wrong.
var ErrInvalidManifest = errors.New("manifest")

// Privilege levels a manifest may declare. Not every module is root.
const (
	PrivilegeSystem  = "system"
	PrivilegeService = "service"
	PrivilegeUser    = "user"
)

// Session placements a manifest may declare.
const (
	SessionSystem         = "system"
	SessionPerUserConsole = "per-user-console"
	SessionPerUserAll     = "per-user-all"
)

// Platform is one os/arch pair a module ships for.
type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// Signing pins the identity core verifies before exec.
type Signing struct {
	AppleTeamID         string `json:"apple_team_id,omitempty"`        //nolint:tagliatelle // module manifest file format (schema/module-manifest.schema.json)
	AuthenticodeSubject string `json:"authenticode_subject,omitempty"` //nolint:tagliatelle // module manifest file format (schema/module-manifest.schema.json)
	// AuthenticodeThumbprint pins the signing certificate's SHA-1
	// thumbprint (40 hex chars, case-insensitive). When set, the Windows
	// verifier pins on it rather than the mutable subject display name.
	AuthenticodeThumbprint string `json:"authenticode_thumbprint,omitempty"` //nolint:tagliatelle // module manifest file format (schema/module-manifest.schema.json)
}

// Artifact is one published binary, stamped by CI.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// Manifest is a module's declaration. See the JSON schema for field
// semantics.
type Manifest struct {
	Schema       int        `json:"schema"`
	ID           string     `json:"id"`
	Version      string     `json:"version"`
	Protocol     uint32     `json:"protocol"`
	Zone         string     `json:"zone"`
	Privilege    string     `json:"privilege"`
	Session      string     `json:"session"`
	Platforms    []Platform `json:"platforms"`
	Capabilities []string   `json:"capabilities,omitempty"`
	// Subscribes lists the event-bus topic patterns this module may
	// subscribe to (exact topics or "<prefix>.*" globs). Core enforces it
	// at Subscribe, so a module cannot firehose another's events. Empty
	// means the module subscribes to nothing.
	Subscribes []string `json:"subscribes,omitempty"`
	// Address is the name the module answers to on the hypervisor channel,
	// when it differs from ID. Per-OS builds of one capability
	// (weave-linux-exec, weave-windows-exec) share an address
	// (weave.exec) so the host never needs to know the guest OS to
	// reach them. Empty means ID.
	Address   string     `json:"address,omitempty"`
	Signing   *Signing   `json:"signing,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	addressRe = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$`)
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	digestRe  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// thumbRe is an Authenticode SHA-1 thumbprint, as the schema has it.
	thumbRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
)

// Parse unmarshals and validates a manifest document.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Load reads and parses a manifest file.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// The *fs.PathError already names the path; errors.Is(err,
		// fs.ErrNotExist) still sees through the wrap.
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return Parse(data)
}

// ChannelAddress is the name core routes hypervisor channel traffic for this
// module under: Address when set, otherwise ID.
func (m *Manifest) ChannelAddress() string {
	if m.Address != "" {
		return m.Address
	}
	return m.ID
}

// Validate checks structural invariants the schema encodes.
func (m *Manifest) Validate() error {
	switch {
	case m.Schema != 1:
		return fmt.Errorf("%w: unsupported schema %d", ErrInvalidManifest, m.Schema)
	case !idRe.MatchString(m.ID):
		return fmt.Errorf("%w: invalid id %q", ErrInvalidManifest, m.ID)
	case m.ID == hvchannel.ControlModule:
		// The hypervisor channel addresses its own control frames — the
		// authentication handshake — to this id, and core intercepts them
		// before delivery. A module published under this name would receive
		// nothing and merely look broken; worse, a module in a position to
		// answer for the channel could answer the handshake. Refuse it here,
		// where the publisher finds out, rather than inside a guest.
		return fmt.Errorf(
			"%w: id %q is reserved for hypervisor channel control frames",
			ErrInvalidManifest,
			m.ID,
		)
	case m.Address != "" && !addressRe.MatchString(m.Address):
		return fmt.Errorf("%w: invalid address %q", ErrInvalidManifest, m.Address)
	case m.Address == hvchannel.ControlModule:
		return fmt.Errorf(
			"%w: address %q is reserved for hypervisor channel control frames",
			ErrInvalidManifest,
			m.Address,
		)
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("%w: invalid version %q", ErrInvalidManifest, m.Version)
	case m.Protocol < 1:
		return fmt.Errorf("%w: protocol must be >= 1", ErrInvalidManifest)
	case m.Zone != "A" && m.Zone != "B" && m.Zone != "C":
		return fmt.Errorf("%w: invalid zone %q", ErrInvalidManifest, m.Zone)
	case m.Privilege != PrivilegeSystem && m.Privilege != PrivilegeService && m.Privilege != PrivilegeUser:
		return fmt.Errorf("%w: invalid privilege %q", ErrInvalidManifest, m.Privilege)
	case m.Session != SessionSystem && m.Session != SessionPerUserConsole && m.Session != SessionPerUserAll:
		return fmt.Errorf("%w: invalid session %q", ErrInvalidManifest, m.Session)
	case len(m.Platforms) == 0:
		return fmt.Errorf("%w: at least one platform required", ErrInvalidManifest)
	case m.Signing != nil && m.Signing.AuthenticodeThumbprint != "" &&
		!thumbRe.MatchString(m.Signing.AuthenticodeThumbprint):
		// Caught here, where the publisher sees it, rather than as a
		// thumbprint mismatch on every guest.
		return fmt.Errorf("%w: authenticode_thumbprint %q is not 40 hex digits",
			ErrInvalidManifest, m.Signing.AuthenticodeThumbprint)
	}
	for _, p := range m.Platforms {
		if err := osArch(p.OS, p.Arch); err != nil {
			return err
		}
	}
	for _, a := range m.Artifacts {
		if err := osArch(a.OS, a.Arch); err != nil {
			return err
		}
		if !digestRe.MatchString(a.Digest) {
			return fmt.Errorf("%w: invalid digest %q", ErrInvalidManifest, a.Digest)
		}
	}
	return nil
}

// SupportsHost reports whether the manifest lists the given os/arch.
func (m *Manifest) SupportsHost(goos, goarch string) bool {
	for _, p := range m.Platforms {
		if p.OS == goos && p.Arch == goarch {
			return true
		}
	}
	return false
}

func osArch(o, a string) error {
	switch o {
	case "darwin", "windows", "linux":
	default:
		return fmt.Errorf("%w: invalid os %q", ErrInvalidManifest, o)
	}
	switch a {
	case "arm64", "amd64":
	default:
		return fmt.Errorf("%w: invalid arch %q", ErrInvalidManifest, a)
	}
	return nil
}
