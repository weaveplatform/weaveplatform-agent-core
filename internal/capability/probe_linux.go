package capability

import (
	"os"
	"path/filepath"
	"strings"
)

// ChannelPortName is the name the host publishes for the agent channel, and the
// only thing that identifies it inside a guest — a virtio-serial port has no
// other distinguishing feature, and the node numbering depends on how many other
// console ports the host happened to configure.
//
// It is a wire contract with the host, which sets the same literal in two places:
// guestweave-macos internal/guestweaveagent/wire.PortName (Virtualization.framework
// guests) and internal/hypervisor/hardware/virtioconsole.PortName (the bespoke
// Windows VMM). A disagreement produces no build error and no runtime error —
// just a guest that never finds its channel.
const ChannelPortName = "org.weave.agent.0"

// probeOS claims hypervisor.channel only when the named port is actually present.
//
// Note what is NOT probed: /dev/vsock. Its presence means the guest has a
// virtio-vsock device, which weave attaches to every VM for unrelated reasons
// (the host's control-socket proxy), so treating it as the channel would claim
// the capability on every guest. Core would then open it, a module needing the channel
// would launch believing it had a channel, and nothing would ever arrive — the
// worst failure shape available, because every log line reads healthy. A channel
// that is genuinely offered over vsock has a port number to connect to, which
// this probe would have to be told; a bare device node is not that. So vsock is
// claimed only when the operator configured a port (-channel vsock:<port>) AND
// the guest has the socket family at all.
func probeOS(set Set, ch Channel) {
	switch ch.Kind {
	case ChannelVsock:
		if exists(filepath.Join(devDir, "vsock")) {
			set["hypervisor.channel"] = ch.socketAttrs()
		}
		return
	case ChannelAuto, ChannelVirtioSerial:
	default:
		return
	}
	dev := channelDevice()
	if dev == "" {
		return
	}
	set["hypervisor.channel"] = map[string]string{
		"kind":   "virtio-serial",
		"device": dev,
	}
}

// Roots, so the probe can be tested against a fabricated /dev and /sys. Nothing
// but a test writes these.
var (
	devDir         = "/dev"
	sysVirtioPorts = "/sys/class/virtio-ports"
)

// channelDevice resolves the named port to a device node, or "" when this guest
// has no weave channel.
func channelDevice() string {
	// The udev-made symlink, when udev is running. It is named for the port, so
	// finding it is proof of identity as well as presence.
	if link := filepath.Join(devDir, "virtio-ports", ChannelPortName); exists(link) {
		return link
	}
	// Without udev there is no symlink, only /dev/vportNpM nodes whose numbering
	// says nothing about which port is which. sysfs still carries the name the
	// host published, so ask it rather than guessing at a node.
	entries, err := os.ReadDir(sysVirtioPorts)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name, err := os.ReadFile(filepath.Join(sysVirtioPorts, e.Name(), "name"))
		if err != nil || strings.TrimSpace(string(name)) != ChannelPortName {
			continue
		}
		if dev := filepath.Join(devDir, e.Name()); exists(dev) {
			return dev
		}
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
