package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func useDevices(t *testing.T, devs ...string) {
	t.Helper()
	old := channelDevices
	channelDevices = devs
	t.Cleanup(func() { channelDevices = old })
}

// The first present node wins, so a guest exposing both the callout node and
// the udev-style path is not reported twice or in the wrong order.
func TestDarwinProbeClaimsTheFirstPresentNode(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "cu.chan"), filepath.Join(dir, "virtio")
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	useDevices(t, filepath.Join(dir, "absent"), first, second)
	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})
	if got := set["hypervisor.channel"]["device"]; got != first {
		t.Fatalf("device = %q, want %q", got, first)
	}
}

func TestDarwinProbeNoNodeNoCapability(t *testing.T) {
	useDevices(t, filepath.Join(t.TempDir(), "absent"))
	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed hypervisor.channel with no device node")
	}
}

func TestDarwinProbeOnlyForDeviceKinds(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "cu.chan")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	useDevices(t, dev)
	set := Set{}
	probeOS(set, Channel{Kind: ChannelVirtioSerial})
	if set["hypervisor.channel"]["device"] != dev {
		t.Fatalf("forced virtio-serial not claimed: %v", set)
	}
	set = Set{}
	probeOS(set, Channel{Kind: ChannelNone})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed a channel with none configured")
	}
}
