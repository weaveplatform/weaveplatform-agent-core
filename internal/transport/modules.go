package transport

import (
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
)

// snapshot renders the registry as the host channel reports it. A nil
// registry is an empty one at revision 0.
func snapshot(reg *registry.Registry) hvchannel.ModulesSnapshot {
	out := hvchannel.ModulesSnapshot{Modules: []hvchannel.ModuleInfo{}}
	if reg == nil {
		return out
	}
	rev, mods := reg.List()
	out.Revision = rev
	if c := reg.Core(); c.Degraded != "" {
		out.Core = &hvchannel.CoreCondition{
			Degraded: true, Reason: c.Degraded, Unavailable: append([]string{}, c.Unavailable...),
		}
	}
	for _, m := range mods {
		caps := m.Capabilities
		if caps == nil {
			// An array, never null: the shape a host decodes into does not
			// change with whether a module happens to require anything.
			caps = []string{}
		}
		out.Modules = append(out.Modules, hvchannel.ModuleInfo{
			ID:           m.ID,
			Version:      m.Version,
			Protocol:     m.Protocol,
			Address:      m.Address,
			Capabilities: caps,
			Privilege:    m.Privilege,
			Session:      m.Session,
			State:        string(m.State),
			Detail:       m.Detail,
			Health: hvchannel.ModuleHealth{
				Status: healthStatus(m.Health),
				Reason: m.Health.GetReason(),
			},
			Restarts: m.Restarts,
			Since:    m.Since.UTC().Format(time.RFC3339Nano),
		})
	}
	return out
}

func healthStatus(h *agentv1.Health) string {
	switch h.GetStatus() {
	case agentv1.Health_STATUS_HEALTHY:
		return hvchannel.HealthHealthy
	case agentv1.Health_STATUS_DEGRADED:
		return hvchannel.HealthDegraded
	case agentv1.Health_STATUS_UNHEALTHY:
		return hvchannel.HealthUnhealthy
	default:
		return hvchannel.HealthUnknown
	}
}
