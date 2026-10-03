package eventbus

import "testing"

func TestPerTopicSequence(t *testing.T) {
	b := New()
	sub := b.Subscribe("m.*")
	defer sub.Close()

	b.Publish("m", "a", nil)
	b.Publish("m", "a", nil)
	b.Publish("m", "b", nil)

	got := map[string]uint64{}
	for i := 0; i < 3; i++ {
		ev := <-sub.C()
		got[ev.Topic] = ev.Sequence
	}
	// Sequence is per-topic: m.a reached 2, m.b reached 1.
	if got["m.a"] != 2 {
		t.Errorf("m.a sequence = %d, want 2", got["m.a"])
	}
	if got["m.b"] != 1 {
		t.Errorf("m.b sequence = %d, want 1", got["m.b"])
	}
}

func TestDropIsVisible(t *testing.T) {
	b := New()
	sub := b.Subscribe("m.*")
	defer sub.Close()

	// The buffer is 64; overflow it without draining.
	for i := 0; i < 64+10; i++ {
		b.Publish("m", "x", nil)
	}
	if sub.Dropped() == 0 {
		t.Fatal("expected dropped events to be counted on a full subscriber")
	}
	// The delivered events still carry monotonic sequences, so the
	// subscriber can see the gap.
	first := <-sub.C()
	if first.Sequence == 0 {
		t.Fatal("delivered event has no sequence")
	}
}

func TestWildcardMatch(t *testing.T) {
	b := New()
	all := b.Subscribe("m.*")
	exact := b.Subscribe("m.one")
	defer all.Close()
	defer exact.Close()

	b.Publish("m", "one", nil)
	b.Publish("m", "two", nil)

	if ev := <-all.C(); ev.Topic != "m.one" {
		t.Errorf("all got %s first", ev.Topic)
	}
	if ev := <-all.C(); ev.Topic != "m.two" {
		t.Errorf("all got %s second", ev.Topic)
	}
	if ev := <-exact.C(); ev.Topic != "m.one" {
		t.Errorf("exact got %s", ev.Topic)
	}
	select {
	case ev := <-exact.C():
		t.Errorf("exact subscriber got unexpected %s", ev.Topic)
	default:
	}
}
