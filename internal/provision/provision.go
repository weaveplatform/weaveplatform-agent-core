// Package provision installs the hypervisor channel's trust anchor from
// host-supplied boot media, for guests that have no cloud-init to do it: macOS
// and Windows.
//
// The host attaches a read-only volume labelled WEAVEPROV holding
// weave/channel.pub. At start, and only while no anchor is installed, core
// copies that key to the anchor path; the channel then authenticates against
// it. This is the same trust class as a cloud-init seed or a key baked into the
// image — boot media the host supplies before anything can talk to the guest —
// and never anything that arrives over the channel itself.
//
// It never replaces an anchor. Anything already at the anchor path, valid or
// not, ends provisioning: the volume is not even read. A guest's trust changes
// only when whoever administers it removes the anchor (weave seal does, before
// the template is cloned), and the next boot then takes the volume's key.
package provision

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/transport"
)

// VolumeLabel is the label the provisioning volume carries.
const VolumeLabel = "WEAVEPROV"

// maxKeyFile bounds what is read from the volume: a key file is 45 bytes, and
// the volume is input core did not write.
const maxKeyFile = 4096

// Defaults for how long a missing volume is waited for. macOS mounts an
// attached disk some seconds into boot, often after core has started; past a
// few minutes a volume that has not appeared is not coming, and a guest with no
// anchor is a legitimate state (an unprovisioned image), not one to poll for
// forever.
const (
	DefaultInterval = 2 * time.Second
	DefaultWindow   = 3 * time.Minute
)

// Outcome is what one attempt found.
type Outcome int

// The outcomes of an attempt.
const (
	// NoVolume: no anchor and no provisioning volume yet.
	NoVolume Outcome = iota
	// AnchorPresent: something is already at the anchor path; nothing done.
	AnchorPresent
	// Installed: the volume's key is now the anchor.
	Installed
	// Refused: a volume or key was found and not trusted. Retrying would read
	// the same media, so provisioning stops.
	Refused
)

func (o Outcome) String() string {
	switch o {
	case NoVolume:
		return "no volume"
	case AnchorPresent:
		return "anchor present"
	case Installed:
		return "installed"
	default:
		return "refused"
	}
}

var (
	errNotRegular  = errors.New("not a regular file")
	errTooLarge    = errors.New("larger than a channel key file")
	errAmbiguous   = errors.New("more than one provisioning volume; refusing to choose")
	errNotReadOnly = errors.New("mounted read-write")
)

// Provisioner installs the anchor from the provisioning volume.
type Provisioner struct {
	Log *slog.Logger
	// AnchorPath is where the channel trust anchor lives
	// (transport.DefaultChannelKeyPath, or --channel-pub).
	AnchorPath string
	// Volumes returns the root of each mounted provisioning volume. An error
	// means a volume was found and is not acceptable (mounted read-write, by a
	// user rather than the system). Nil takes the platform's lookup.
	Volumes func() ([]string, error)
	// Interval and Window: how often, and for how long, a missing volume is
	// looked for again. Zero takes the defaults.
	Interval, Window time.Duration
}

// Start makes one attempt now, so a volume already mounted is installed before
// the channel loads its key, then keeps looking in the background while there
// is neither an anchor nor a volume, for at most Window. The returned channel
// closes when it has stopped looking.
func (p *Provisioner) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if p.attempt() != NoVolume {
		close(done)
		return done
	}
	interval, window := p.Interval, p.Window
	if interval <= 0 {
		interval = DefaultInterval
	}
	if window <= 0 {
		window = DefaultWindow
	}
	go func() {
		defer close(done)
		deadline := time.NewTimer(window)
		defer deadline.Stop()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				p.log().
					Info("no provisioning volume appeared; the hypervisor channel stays unprovisioned",
						"label", VolumeLabel, "waited", window)
				return
			case <-tick.C:
				if p.attempt() != NoVolume {
					return
				}
			}
		}
	}()
	return done
}

// attempt is Once with its result logged.
func (p *Provisioner) attempt() Outcome {
	out, err := p.Once()
	if err != nil {
		p.log().Error("provisioning volume refused; the hypervisor channel stays unprovisioned",
			"label", VolumeLabel, "anchor", p.AnchorPath, "err", err)
	}
	return out
}

// Once makes one attempt.
func (p *Provisioner) Once() (Outcome, error) {
	switch _, err := os.Lstat(p.AnchorPath); {
	case err == nil:
		return AnchorPresent, nil
	case !errors.Is(err, fs.ErrNotExist):
		// Cannot tell whether there is an anchor, so cannot be sure of not
		// replacing one.
		return Refused, fmt.Errorf("checking for a trust anchor at %s: %w", p.AnchorPath, err)
	}
	lookup := p.Volumes
	if lookup == nil {
		lookup = platformVolumes
	}
	vols, err := lookup()
	if err != nil {
		return Refused, err
	}
	switch len(vols) {
	case 0:
		return NoVolume, nil
	case 1:
	default:
		return Refused, fmt.Errorf("%w: %v", errAmbiguous, vols)
	}
	src := filepath.Join(vols[0], "weave", "channel.pub")
	key, err := readKey(src)
	if err != nil {
		return Refused, fmt.Errorf("provisioning key %s: %w", src, err)
	}
	installed, err := install(p.AnchorPath, key)
	if err != nil {
		return Refused, err
	}
	if !installed {
		return AnchorPresent, nil
	}
	p.log().Info("hypervisor channel trust anchor installed from the provisioning volume",
		"source", src, "anchor", p.AnchorPath, "fingerprint", transport.KeyFingerprint(key))
	return Installed, nil
}

func (p *Provisioner) log() *slog.Logger {
	if p.Log == nil {
		return slog.Default()
	}
	return p.Log
}

// readKey reads and validates the volume's key. A symlink is refused rather
// than followed: the key is the file on the medium, not whatever in the guest
// a link on it names.
func readKey(path string) (ed25519.PublicKey, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	if len(raw) > maxKeyFile {
		return nil, errTooLarge
	}
	key, err := transport.ParseChannelKey(raw)
	if err != nil {
		return nil, fmt.Errorf("not a channel key: %w", err)
	}
	return key, nil
}

// install writes key at path unless something is already there. installed is
// false when something is.
//
// The key is written in full to a temporary sibling, given its final owner
// and mode, then hard-linked to path. A link, unlike a rename, fails when path
// exists, so even an anchor that appeared since Once looked is never replaced;
// and path only ever appears complete — a truncated anchor would be worse than
// none, because it would never be replaced either.
func install(path string, key ed25519.PublicKey) (installed bool, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".channel.pub-*")
	if err != nil {
		return false, fmt.Errorf("staging the anchor in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, werr := tmp.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o644)
	}
	if werr == nil {
		werr = secureAnchor(name)
	}
	if werr != nil {
		return false, fmt.Errorf("staging the anchor: %w", werr)
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("installing the anchor at %s: %w", path, err)
	}
	return true, nil
}
