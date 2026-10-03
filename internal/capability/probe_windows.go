package capability

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// guestParamsKey is a var so the probe can be tested on hosts that are, or
// are not, Hyper-V guests; nothing but a test writes it.
var guestParamsKey = `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`

// channelDevices are where a Windows guest presents a virtio-serial channel:
// the vioserial named device, then COM2 (they enumerate on different
// schedules). Only consulted when virtio-serial is configured explicitly; a var
// so tests can point it at files.
var channelDevices = []string{
	`\\.\Global\org.weave.agent.0`,
	`\\.\COM2`,
}

func probeOS(set Set, ch Channel) {
	switch ch.Kind {
	case ChannelAuto:
		// A Hyper-V guest exposes the virtualization guest parameters key.
		// Without a configured port this claims kind=hvsocket with nothing to
		// listen on, and the transport falls back to the virtio-serial device
		// candidates: the historical default, kept as it was.
		if hyperVGuest() {
			set["hypervisor.channel"] = map[string]string{"kind": ChannelHvSocket}
		}
	case ChannelHvSocket:
		if hyperVGuest() {
			set["hypervisor.channel"] = ch.socketAttrs()
		}
	case ChannelVirtioSerial:
		// Opening is the probe: \\.\ device names do not answer os.Stat.
		for _, dev := range channelDevices {
			if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
				f.Close()
				set["hypervisor.channel"] = map[string]string{
					"kind":   ChannelVirtioSerial,
					"device": dev,
				}
				return
			}
		}
	}
}

func hyperVGuest() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, guestParamsKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}
