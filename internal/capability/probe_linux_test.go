package capability

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests exist because this probe decides whether a channel module is
// ever launched: a module whose capabilities are unmet goes to
// StateRequirementsUnmet and never runs, and a probe that claims the capability
// on the wrong node gives core a channel that never delivers a frame. Both
// failures look like a healthy boot.

func TestProbeFindsTheUdevSymlink(t *testing.T) {
	dev := t.TempDir()
	writeFile(t, filepath.Join(dev, "virtio-ports", ChannelPortName), "")
	useRoots(t, dev, filepath.Join(t.TempDir(), "absent"))

	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})

	attrs, ok := set["hypervisor.channel"]
	if !ok {
		t.Fatal("named port present but capability not claimed")
	}
	if want := filepath.Join(dev, "virtio-ports", ChannelPortName); attrs["device"] != want {
		t.Errorf("device = %q, want %q", attrs["device"], want)
	}
	if attrs["kind"] != "virtio-serial" {
		t.Errorf("kind = %q, want virtio-serial", attrs["kind"])
	}
}

// A guest without udev has no symlink, only vportNpM nodes. sysfs still carries
// the name the host published; the node numbering does not.
func TestProbeResolvesThePortByNameWithoutUdev(t *testing.T) {
	dev, sys := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(sys, "vport0p1", "name"), "org.qemu.guest_agent.0\n")
	writeFile(t, filepath.Join(sys, "vport0p2", "name"), ChannelPortName+"\n")
	writeFile(t, filepath.Join(dev, "vport0p1"), "")
	writeFile(t, filepath.Join(dev, "vport0p2"), "")
	useRoots(t, dev, sys)

	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})

	if got, want := set["hypervisor.channel"]["device"], filepath.Join(
		dev,
		"vport0p2",
	); got != want {
		t.Errorf(
			"device = %q, want %q — the port must be chosen by name, not by position",
			got,
			want,
		)
	}
}

// The regression this file was written for: /dev/vsock is present in every weave
// guest (the host attaches a virtio-socket device for its control-socket proxy),
// and an earlier probe claimed the channel on it. Core then opened a device that
// never yields a frame, so the module started and simply never heard anything.
func TestProbeIgnoresVsockAndOtherPorts(t *testing.T) {
	dev, sys := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dev, "vsock"), "")
	writeFile(t, filepath.Join(dev, "hvc0"), "")
	writeFile(t, filepath.Join(sys, "vport0p1", "name"), "org.qemu.guest_agent.0\n")
	writeFile(t, filepath.Join(dev, "vport0p1"), "")
	useRoots(t, dev, sys)

	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})

	if attrs, ok := set["hypervisor.channel"]; ok {
		t.Fatalf("claimed hypervisor.channel with no weave port present: %v", attrs)
	}
}

// A sysfs entry naming the port, with no matching device node, is a guest whose
// channel is not usable. Reporting it would hand core an unopenable path.
func TestProbeRequiresTheDeviceNodeToExist(t *testing.T) {
	dev, sys := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(sys, "vport0p2", "name"), ChannelPortName+"\n")
	useRoots(t, dev, sys)

	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})

	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed the capability for a port with no device node")
	}
}

func useRoots(t *testing.T, dev, sys string) {
	t.Helper()
	oldDev, oldSys := devDir, sysVirtioPorts
	devDir, sysVirtioPorts = dev, sys
	t.Cleanup(func() { devDir, sysVirtioPorts = oldDev, oldSys })
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// No udev symlink and no sysfs class (a kernel without virtio-console): no
// channel, and no error to trip over either.
func TestProbeWithoutSysfsClaimsNothing(t *testing.T) {
	useRoots(t, t.TempDir(), filepath.Join(t.TempDir(), "absent"))
	set := Set{}
	probeOS(set, Channel{Kind: ChannelAuto})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed the capability with no sysfs to resolve the port")
	}
}

// vsock is claimed only when configured, and then only on a guest that has the
// socket family at all; the attrs carry the port the transport listens on.
func TestProbeConfiguredVsock(t *testing.T) {
	dev := t.TempDir()
	useRoots(t, dev, filepath.Join(t.TempDir(), "absent"))
	vsock := Channel{Kind: ChannelVsock, Port: 2010}

	set := Set{}
	probeOS(set, vsock)
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed vsock on a guest without /dev/vsock")
	}

	writeFile(t, filepath.Join(dev, "vsock"), "")
	set = Set{}
	probeOS(set, vsock)
	if got := set["hypervisor.channel"]; got["kind"] != "vsock" || got["port"] != "2010" {
		t.Fatalf("attrs = %v, want kind=vsock port=2010", got)
	}
}

// Configuring vsock replaces the device probe rather than adding to it: a
// guest that also has the named port must not end up with the module talking
// to one wire while the host listens on the other.
func TestProbeConfiguredVsockIgnoresTheSerialPort(t *testing.T) {
	dev := t.TempDir()
	writeFile(t, filepath.Join(dev, "virtio-ports", ChannelPortName), "")
	useRoots(t, dev, filepath.Join(t.TempDir(), "absent"))
	set := Set{}
	probeOS(set, Channel{Kind: ChannelVsock, Port: 2010})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatalf(
			"claimed %v; vsock was configured and /dev/vsock is absent",
			set["hypervisor.channel"],
		)
	}
	set = Set{}
	probeOS(set, Channel{Kind: ChannelVirtioSerial})
	if set["hypervisor.channel"]["kind"] != "virtio-serial" {
		t.Fatalf("virtio-serial forced but not claimed: %v", set)
	}
	set = Set{}
	probeOS(set, Channel{Kind: ChannelNone})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatal("claimed a channel with none configured")
	}
}
