// Package eventbus is core's in-process pub/sub: the only lateral channel
// between modules. Delivery is at-most-once and unpersisted — a slow
// subscriber drops events rather than stalling the bus or the publisher.
package eventbus

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one published event as seen by subscribers.
type Event struct {
	// Topic arrives prefixed with the publishing module's id; the bus
	// stamps it so subscribers can trust the origin.
	Topic       string
	Data        []byte
	PublishedAt time.Time
	// Sequence is a monotonic per-topic counter stamped by the bus. A gap
	// in a subscriber's received sequence for a topic means it missed
	// events (delivery is at-most-once) and should re-pull state.
	Sequence uint64
}

// Bus fans events out to subscribers.
type Bus struct {
	mu   sync.Mutex
	subs map[*Subscription]struct{}
	seq  map[string]uint64 // per-topic monotonic sequence
}

// New returns an empty bus.
func New() *Bus {
	return &Bus{subs: make(map[*Subscription]struct{}), seq: make(map[string]uint64)}
}

// Publish stamps and delivers the event. from is the publishing module's
// id and becomes the topic prefix; core is "core".
func (b *Bus) Publish(from, topic string, data []byte) {
	fullTopic := from + "." + topic
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq[fullTopic]++
	ev := Event{Topic: fullTopic, Data: data, PublishedAt: time.Now(), Sequence: b.seq[fullTopic]}
	for s := range b.subs {
		if s.matches(ev.Topic) {
			select {
			case s.ch <- ev:
			default:
				// At-most-once: a full subscriber loses this event. The
				// gap is visible to it via the sequence.
				s.dropped.Add(1)
			}
		}
	}
}

// Subscription is one subscriber's feed.
type Subscription struct {
	bus     *Bus
	topics  []string
	ch      chan Event
	dropped atomic.Uint64
}

// Subscribe registers for topics (exact, or prefix globs like "presence.*")
// with a buffered feed. Close the subscription when done.
func (b *Bus) Subscribe(topics ...string) *Subscription {
	s := &Subscription{bus: b, topics: topics, ch: make(chan Event, 64)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// C is the event feed.
func (s *Subscription) C() <-chan Event { return s.ch }

// Dropped returns how many events this subscription lost to a full buffer.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Close unregisters the subscription.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	delete(s.bus.subs, s)
	s.bus.mu.Unlock()
}

func (s *Subscription) matches(topic string) bool {
	for _, p := range s.topics {
		if p == topic {
			return true
		}
		if pre, ok := strings.CutSuffix(p, "*"); ok && strings.HasPrefix(topic, pre) {
			return true
		}
	}
	return false
}
