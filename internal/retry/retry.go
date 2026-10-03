// Package retry provides exponential backoff with jitter. It is a policy
// calculator, not a loop runner: callers own their loops and contexts and
// ask Backoff what to wait. The same curve serves transport reconnection in
// core and the supervisor's crash-loop damping.
package retry

import (
	"math/rand/v2"
	"time"
)

// Backoff computes exponentially growing delays with full jitter.
// The zero value is not usable; use New or fill every field.
type Backoff struct {
	// Initial is the base delay for attempt 0.
	Initial time.Duration
	// Max caps the computed delay.
	Max time.Duration
	// Factor multiplies the delay each attempt. Typically 2.
	Factor float64
}

// New returns a Backoff with the conventional platform curve:
// 1s initial, doubling, capped at 2 minutes.
func New() Backoff {
	return Backoff{Initial: time.Second, Max: 2 * time.Minute, Factor: 2}
}

// Delay returns the wait before the given attempt (0-based), with full
// jitter: a uniform draw from (0, computed]. Full jitter avoids thundering
// herds when many modules restart together.
func (b Backoff) Delay(attempt int) time.Duration {
	d := float64(b.Initial)
	for i := 0; i < attempt; i++ {
		d *= b.Factor
		if d >= float64(b.Max) {
			d = float64(b.Max)
			break
		}
	}
	// Jitter only spreads restarts; it is not a secret and needs no CSPRNG.
	return time.Duration(rand.Float64() * d) //nolint:gosec // non-security jitter
}
