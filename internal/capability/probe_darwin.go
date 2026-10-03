package capability

import "os"

// channelDevices are the nodes a Weave virtio-serial channel appears as, in
// preference order. A var so the probe can be tested against fabricated
// nodes; nothing but a test writes it.
var channelDevices = []string{
	"/dev/cu.org.weave.agent.0",
	"/dev/virtio-ports/org.weave.agent.0",
}

func probeOS(set Set, ch Channel) {
	// hypervisor.channel: present when running as a VM guest with a Weave
	// virtio-serial channel. The device node is the probe. Socket channels are
	// rejected for this OS when the configuration is parsed.
	if ch.Kind != ChannelAuto && ch.Kind != ChannelVirtioSerial {
		return
	}
	for _, dev := range channelDevices {
		if _, err := os.Stat(dev); err == nil {
			set["hypervisor.channel"] = map[string]string{"device": dev}
			break
		}
	}
}
