package supervise

import "github.com/weaveplatform/weaveplatform-agent-core/internal/registry"

// State is a supervised module's lifecycle state; the vocabulary is the
// registry's, so every view of a module reports the same words.
type State = registry.State

// The lifecycle states; see registry for what each means.
const (
	StatePending             = registry.StatePending
	StateStarting            = registry.StateStarting
	StateRunning             = registry.StateRunning
	StateBackoff             = registry.StateBackoff
	StateStartLimited        = registry.StateStartLimited
	StateUnsupportedProtocol = registry.StateUnsupportedProtocol
	StateRequirementsUnmet   = registry.StateRequirementsUnmet
	StateWaitingForSession   = registry.StateWaitingForSession
	StateStopped             = registry.StateStopped
	StateInvalid             = registry.StateInvalid
)

// Status is one module's supervision snapshot: its registry entry.
type Status = registry.Module
