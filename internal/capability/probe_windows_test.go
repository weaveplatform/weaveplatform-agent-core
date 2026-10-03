package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func useGuestKey(t *testing.T, key string) {
	t.Helper()
	old := guestParamsKey
	guestParamsKey = key
	t.Cleanup(func() { guestParamsKey = old })
}

const (
	presentKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	absentKey  = `SOFTWARE\Weave\DefinitelyNotAGuestKey`
)

// CI runners may or may not be Hyper-V guests, so both outcomes are driven
// through keys whose presence is known rather than through the real one.
func TestWindowsProbeClaimsWhenTheGuestKeyExists(t *testing.T) {
	useGuestKey(t, presentKey)
	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})
	if got := set["hypervisor.channel"]; got["kind"] != "hvsocket" || got["port"] != "" {
		t.Fatalf("auto on a Hyper-V guest: %v, want kind=hvsocket and no port", set)
	}
}

func TestWindowsProbeAbsentKeyNoCapability(t *testing.T) {
	useGuestKey(t, absentKey)
	for _, ch := range []Channel{{Kind: ChannelAuto}, {Kind: ChannelHvSocket, Port: 2010}, {Kind: ChannelNone}} {
		set := Set{}
		probeOS(set, ch)
		if _, ok := set["hypervisor.channel"]; ok {
			t.Fatalf("%s claimed hypervisor.channel without the guest key", ch)
		}
	}
}

func TestWindowsProbeConfiguredHvSocket(t *testing.T) {
	useGuestKey(t, presentKey)
	set := Set{}
	probeOS(set, Channel{Kind: ChannelHvSocket, Port: 2010})
	if got := set["hypervisor.channel"]; got["kind"] != "hvsocket" || got["port"] != "2010" {
		t.Fatalf("attrs = %v, want kind=hvsocket port=2010", got)
	}
}

func TestWindowsProbeForcedVirtioSerial(t *testing.T) {
	dir := t.TempDir()
	dev := filepath.Join(dir, "vport")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := channelDevices
	t.Cleanup(func() { channelDevices = old })

	channelDevices = []string{filepath.Join(dir, "absent"), dev}
	set := Set{}
	probeOS(set, Channel{Kind: ChannelVirtioSerial})
	if got := set["hypervisor.channel"]; got["kind"] != "virtio-serial" || got["device"] != dev {
		t.Fatalf("attrs = %v, want the first openable device", got)
	}

	channelDevices = []string{filepath.Join(dir, "absent")}
	set = Set{}
	probeOS(set, Channel{Kind: ChannelVirtioSerial})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed virtio-serial with no openable device")
	}
}
