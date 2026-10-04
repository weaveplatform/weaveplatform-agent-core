package hvchannel

// The module registry and undeliverable-message frames, all addressed to
// ControlModule. Like every control kind but the auth handshake, they cross
// only an authenticated channel: before authentication a modules.list is
// refused like any module operation, and neither modules.changed nor
// delivery.failed is sent, because both say which modules a guest has.
const (
	// KindModulesList: host → guest. Asks for the registry. Carries no
	// payload; the envelope ID, if any, is echoed on the result.
	KindModulesList = "modules.list"
	// KindModulesListResult: guest → host. ModulesSnapshot.
	KindModulesListResult = "modules.list.result"
	// KindModulesChanged: guest → host, unsolicited. ModulesSnapshot, sent
	// whenever a module is added or removed or its state or health changes,
	// while the channel is authenticated.
	KindModulesChanged = "modules.changed"
	// KindDeliveryFailed: guest → host. DeliveryFailed, sent in place of the
	// reply a host would otherwise wait out a timeout for. The envelope ID
	// echoes the undeliverable frame's.
	KindDeliveryFailed = "delivery.failed"
)

// ModulesSnapshot is the whole registry at one revision. Revision only ever
// increases for the life of a core process, so a host keeps the snapshot with
// the higher one; it restarts from 1 when core does.
type ModulesSnapshot struct {
	Revision uint64       `json:"revision"`
	Modules  []ModuleInfo `json:"modules"`
}

// ModuleInfo is one installed module as a host sees it.
type ModuleInfo struct {
	ID           string       `json:"id"`
	Version      string       `json:"version"`
	Protocol     uint32       `json:"protocol"`
	Address      string       `json:"address"`
	Capabilities []string     `json:"capabilities"`
	Privilege    string       `json:"privilege"`
	Session      string       `json:"session"`
	State        string       `json:"state"`
	Detail       string       `json:"detail,omitempty"`
	Health       ModuleHealth `json:"health"`
	Restarts     uint32       `json:"restarts"`
	// Since is when the module entered State, RFC 3339 in UTC.
	Since string `json:"since"`
}

// ModuleHealth is a module's last health report.
type ModuleHealth struct {
	// Status is HealthUnknown until the module has been polled.
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Health statuses.
const (
	HealthUnknown   = "unknown"
	HealthHealthy   = "healthy"
	HealthDegraded  = "degraded"
	HealthUnhealthy = "unhealthy"
)

// DeliveryFailed says why core could not hand a frame to a module.
type DeliveryFailed struct {
	// Module and Kind are the undeliverable frame's own.
	Module string `json:"module"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	// State is the module's lifecycle state; set only for ReasonNotRunning.
	State  string `json:"state,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Delivery failure reasons.
const (
	// ReasonNotInstalled: no module answers to the address.
	ReasonNotInstalled = "not_installed"
	// ReasonNotRunning: a module answers to the address but has no receiver
	// open — it is starting, waiting for a console session, crashed, stopped
	// or refused; State says which.
	ReasonNotRunning = "not_running"
	// ReasonBusy: the module's receive queue is full. A retry may succeed.
	ReasonBusy = "busy"
)
