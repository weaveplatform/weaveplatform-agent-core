package supervise

import (
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
)

// State is a supervised module's lifecycle state as reported to operators.
type State string

const (
	// StatePending: registered, not yet launched.
	StatePending State = "pending"
	// StateStarting: spawn through handshake through Start.
	StateStarting State = "starting"
	// StateRunning: started and passing health checks.
	StateRunning State = "running"
	// StateBackoff: crashed; waiting out the restart delay.
	StateBackoff State = "backoff"
	// StateStartLimited: hit the start-limit (too many restarts in the
	// window); not restarting. Fail closed: an operator (or a rollback)
	// resets it. This is systemd's StartLimit, not a Fowler circuit breaker
	// (there is no half-open probe; it gates restarts, not calls).
	StateStartLimited State = "start-limited"
	// StateUnsupportedProtocol: the module refused the advertised window
	// (exit 78). Restarting cannot help; not a crash loop.
	StateUnsupportedProtocol State = "unsupported-protocol"
	// StateRequirementsUnmet: the manifest requires capabilities this
	// host lacks. Never launched.
	StateRequirementsUnmet State = "requirements-unmet"
	// StateWaitingForSession: a per-user-console module with nobody at the
	// console. Not a failure: it starts when a user logs in.
	StateWaitingForSession State = "waiting-for-session"
	// StateStopped: cleanly stopped (core shutdown or operator).
	StateStopped State = "stopped"
)

// Status is one module's supervision snapshot.
type Status struct {
	ID       string
	Version  string
	Protocol uint32
	State    State
	// Detail explains non-running states (missing caps, breaker cause).
	Detail   string
	PID      int
	Restarts uint32
	// Health is the last poll result; zero value when never polled.
	Health   *agentv1.Health
	Since    time.Time
	Surfaces []*agentv1.Surface
}
