// Package capability performs the one host inventory at startup. Modules
// declare what they require; core probes once and never launches a module
// whose requirements are unmet. No module calls a probe at its own call
// site — that rule turns a panic on an unbound symbol into a startup log
// line.
package capability

import (
	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
)

// Set is the probed capability inventory: name → attributes.
type Set map[string]map[string]string

// Has reports whether every named capability is present.
func (s Set) Has(names ...string) (missing []string) {
	for _, n := range names {
		if _, ok := s[n]; !ok {
			missing = append(missing, n)
		}
	}
	return missing
}

// Probe inventories the host with the default (auto) hypervisor channel.
func Probe() Set { return ProbeWith(Channel{Kind: ChannelAuto}) }

// ProbeWith inventories the host, claiming hypervisor.channel according to the
// configured channel. It runs once, at core startup.
func ProbeWith(ch Channel) Set {
	info := platform.Host()
	set := Set{
		// platform.osinfo: the host can describe itself. Always present;
		// its attributes carry what was learned.
		"platform.osinfo": {
			"os":       info.OS,
			"arch":     info.Arch,
			"version":  info.Version,
			"build":    info.Build,
			"hostname": info.Hostname,
		},
	}
	// A unix channel is the same on every OS and needs no probing: core
	// creates the socket, and whether a container host is there to dial it
	// is not something the guest can know in advance.
	if ch.Kind == ChannelUnix {
		set["hypervisor.channel"] = ch.unixAttrs()
		return set
	}
	probeOS(set, ch)
	return set
}
