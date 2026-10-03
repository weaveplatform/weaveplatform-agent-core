package retry

import (
	"testing"
	"time"
)

func TestNewIsThePlatformCurve(t *testing.T) {
	b := New()
	if b.Initial != time.Second || b.Max != 2*time.Minute || b.Factor != 2 {
		t.Fatalf("New() = %+v", b)
	}
}

func TestDelayStaysWithinTheCurve(t *testing.T) {
	b := Backoff{Initial: 100 * time.Millisecond, Max: time.Second, Factor: 2}
	for attempt, ceiling := range []time.Duration{
		100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond,
		800 * time.Millisecond, time.Second, time.Second,
	} {
		for range 200 {
			d := b.Delay(attempt)
			if d < 0 || d > ceiling {
				t.Fatalf("Delay(%d) = %v, outside [0,%v]", attempt, d, ceiling)
			}
		}
	}
}

func TestDelayCapsLargeAttempts(t *testing.T) {
	b := New()
	for range 200 {
		if d := b.Delay(1 << 20); d > b.Max {
			t.Fatalf("Delay past the cap: %v", d)
		}
	}
}
