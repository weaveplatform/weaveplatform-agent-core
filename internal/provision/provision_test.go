package provision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/transport"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// volume makes a directory standing in for /Volumes/WEAVEPROV holding
// weave/channel.pub with contents, and returns its root.
func volume(t *testing.T, contents string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "weave"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "weave", "channel.pub"),
		[]byte(contents),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	return root
}

func newKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

func fixed(roots ...string) func() ([]string, error) {
	return func() ([]string, error) { return roots, nil }
}

func anchorPath(t *testing.T) string {
	t.Helper()
	// A directory that does not exist yet, as /etc/weave on a fresh guest.
	return filepath.Join(t.TempDir(), "etc", "weave", "channel.pub")
}

// No anchor and a valid volume: the key is installed, canonically encoded,
// readable by everyone and loadable by the channel.
func TestInstallsFromTheVolume(t *testing.T) {
	pub, enc := newKey(t)
	anchor := anchorPath(t)
	p := &Provisioner{
		Log:        quiet(),
		AnchorPath: anchor,
		Volumes:    fixed(volume(t, "  "+enc+"\r\n\n")),
	}
	out, err := p.Once()
	if err != nil || out != Installed {
		t.Fatalf("Once = %v, %v", out, err)
	}
	raw, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != enc+"\n" {
		t.Fatalf("anchor holds %q", raw)
	}
	got, err := transport.ParseChannelKey(raw)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("anchor does not load as the volume's key: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(anchor)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("anchor mode %04o", fi.Mode().Perm())
		}
	}
	// Nothing staged is left beside it.
	entries, _ := os.ReadDir(filepath.Dir(anchor))
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}
	// The next start finds it and leaves it.
	if out, err := p.Once(); out != AnchorPresent || err != nil {
		t.Fatalf("second Once = %v, %v", out, err)
	}
}

// An existing anchor is never replaced, whether or not it is a usable key, and
// the volume is not even looked for.
func TestNeverReplacesAnAnchor(t *testing.T) {
	_, enc := newKey(t)
	_, other := newKey(t)
	for name, existing := range map[string]string{
		"valid":   other + "\n",
		"garbage": "not a key",
		"empty":   "",
	} {
		t.Run(name, func(t *testing.T) {
			anchor := anchorPath(t)
			if err := os.MkdirAll(filepath.Dir(anchor), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(anchor, []byte(existing), 0o644); err != nil {
				t.Fatal(err)
			}
			looked := false
			p := &Provisioner{Log: quiet(), AnchorPath: anchor, Volumes: func() ([]string, error) {
				looked = true
				return []string{volume(t, enc)}, nil
			}}
			if out, err := p.Once(); out != AnchorPresent || err != nil {
				t.Fatalf("Once = %v, %v", out, err)
			}
			if looked {
				t.Fatal("looked for a volume with an anchor in place")
			}
			if raw, _ := os.ReadFile(anchor); string(raw) != existing {
				t.Fatalf("anchor changed to %q", raw)
			}
		})
	}
}

// An anchor that appears between the check and the install (another core, an
// administrator) wins: the link refuses to replace it.
func TestInstallLosesARaceRatherThanReplace(t *testing.T) {
	pub, _ := newKey(t)
	anchor := anchorPath(t)
	if err := os.MkdirAll(filepath.Dir(anchor), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchor, []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed, err := install(anchor, pub)
	if installed || err != nil {
		t.Fatalf("install = %v, %v", installed, err)
	}
	if raw, _ := os.ReadFile(anchor); string(raw) != "theirs" {
		t.Fatalf("anchor replaced with %q", raw)
	}
}

// A volume whose key is not one Ed25519 key in the one encoding is refused,
// and nothing is installed.
func TestRefusesABadKey(t *testing.T) {
	_, enc := newKey(t)
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	cases := map[string]func(t *testing.T) string{
		"not base64":  func(t *testing.T) string { return volume(t, "!!"+enc) },
		"wrong size":  func(t *testing.T) string { return volume(t, short) },
		"url base64":  func(t *testing.T) string { return volume(t, strings.NewReplacer("+", "-", "/", "_").Replace(enc)+"x") },
		"empty":       func(t *testing.T) string { return volume(t, "") },
		"too large":   func(t *testing.T) string { return volume(t, enc+strings.Repeat(" ", maxKeyFile)) },
		"no key file": func(t *testing.T) string { return t.TempDir() },
		"a directory": func(t *testing.T) string {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "weave", "channel.pub"), 0o755); err != nil {
				t.Fatal(err)
			}
			return root
		},
	}
	if runtime.GOOS != "windows" {
		cases["a symlink"] = func(t *testing.T) string {
			target := filepath.Join(volume(t, enc), "weave", "channel.pub")
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "weave"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "weave", "channel.pub")); err != nil {
				t.Fatal(err)
			}
			return root
		}
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			anchor := anchorPath(t)
			p := &Provisioner{Log: quiet(), AnchorPath: anchor, Volumes: fixed(mk(t))}
			if out, err := p.Once(); out != Refused || err == nil {
				t.Fatalf("Once = %v, %v", out, err)
			}
			if _, err := os.Lstat(anchor); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an anchor was installed: %v", err)
			}
		})
	}
}

// Two provisioning volumes, or one the platform will not accept: nothing is
// chosen.
func TestRefusesAmbiguousOrUnacceptableVolumes(t *testing.T) {
	_, enc := newKey(t)
	anchor := anchorPath(t)
	p := &Provisioner{
		Log:        quiet(),
		AnchorPath: anchor,
		Volumes:    fixed(volume(t, enc), volume(t, enc)),
	}
	if out, err := p.Once(); out != Refused || !errors.Is(err, errAmbiguous) {
		t.Fatalf("two volumes: %v, %v", out, err)
	}
	p.Volumes = func() ([]string, error) { return nil, errNotReadOnly }
	if out, err := p.Once(); out != Refused || !errors.Is(err, errNotReadOnly) {
		t.Fatalf("unacceptable volume: %v, %v", out, err)
	}
	if _, err := os.Lstat(anchor); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an anchor was installed")
	}
}

// No volume: nothing installed, and Start stops looking once its window is
// over rather than polling for the life of core.
func TestNothingWithoutAVolumeAndTheLookIsBounded(t *testing.T) {
	anchor := anchorPath(t)
	var calls atomic.Int32
	p := &Provisioner{
		Log:        quiet(),
		AnchorPath: anchor,
		Interval:   5 * time.Millisecond,
		Window:     100 * time.Millisecond,
		Volumes:    func() ([]string, error) { calls.Add(1); return nil, nil },
	}
	select {
	case <-p.Start(context.Background()):
	case <-time.After(5 * time.Second):
		t.Fatal("Start kept looking past its window")
	}
	n := calls.Load()
	if n < 2 {
		t.Fatalf("looked %d times; a late volume would have been missed", n)
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("still looking after Start finished")
	}
	if _, err := os.Lstat(anchor); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an anchor was installed")
	}
}

// macOS mounts the volume some time into boot: one that appears after core
// started is installed.
func TestVolumeAppearsLate(t *testing.T) {
	pub, enc := newKey(t)
	anchor := anchorPath(t)
	root := volume(t, enc)
	var calls atomic.Int32
	p := &Provisioner{
		Log: quiet(), AnchorPath: anchor, Interval: 5 * time.Millisecond, Window: 10 * time.Second,
		Volumes: func() ([]string, error) {
			if calls.Add(1) < 5 {
				return nil, nil
			}
			return []string{root}, nil
		},
	}
	select {
	case <-p.Start(context.Background()):
	case <-time.After(5 * time.Second):
		t.Fatal("a late volume was never installed")
	}
	raw, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := transport.ParseChannelKey(raw); err != nil || !got.Equal(pub) {
		t.Fatalf("installed %q", raw)
	}
}

// A volume already mounted is installed before Start returns, so the channel
// loads it on its first read.
func TestStartInstallsAMountedVolumeAtOnce(t *testing.T) {
	_, enc := newKey(t)
	anchor := anchorPath(t)
	p := &Provisioner{AnchorPath: anchor, Volumes: fixed(volume(t, enc))}
	done := p.Start(context.Background())
	if _, err := os.Stat(anchor); err != nil {
		t.Fatalf("not installed when Start returned: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Start still looking after installing")
	}
}

func TestStartStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Provisioner{Log: quiet(), AnchorPath: anchorPath(t), Volumes: fixed()}
	done := p.Start(ctx)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start outlived its context")
	}
}

// Where the anchor cannot even be checked or written, nothing is installed and
// the reason is reported.
func TestUnusableAnchorDirectory(t *testing.T) {
	pub, enc := newKey(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := install(filepath.Join(file, "weave", "channel.pub"), pub); err == nil {
		t.Fatal("installed beneath a regular file")
	}
	if runtime.GOOS == "windows" {
		return
	}
	// ENOTDIR from the check itself: not "absent", so not safe to install.
	p := &Provisioner{
		Log:        quiet(),
		AnchorPath: filepath.Join(file, "channel.pub"),
		Volumes:    fixed(volume(t, enc)),
	}
	if out, err := p.Once(); out != Refused || err == nil {
		t.Fatalf("Once = %v, %v", out, err)
	}
	// A directory core cannot write: the staging fails.
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := install(filepath.Join(ro, "channel.pub"), pub); err == nil {
			t.Fatal("installed into a read-only directory")
		}
	}
}

func TestOutcomeStrings(t *testing.T) {
	for o, want := range map[Outcome]string{
		NoVolume: "no volume", AnchorPresent: "anchor present", Installed: "installed", Refused: "refused",
	} {
		if o.String() != want {
			t.Fatalf("%d = %q", o, o.String())
		}
	}
	if (&Provisioner{}).log() != slog.Default() {
		t.Fatal("nil Log is not the default logger")
	}
}

// The platform lookup is what runs when Volumes is nil; on a test machine
// there is no provisioning volume, so it finds none.
func TestPlatformLookupByDefault(t *testing.T) {
	p := &Provisioner{Log: quiet(), AnchorPath: anchorPath(t)}
	out, err := p.Once()
	if err != nil || out != NoVolume {
		t.Skipf("this machine has a provisioning volume mounted: %v, %v", out, err)
	}
}
