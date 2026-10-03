package handshake

import "testing"

// FuzzParse asserts Parse never panics on arbitrary input and that any line
// it accepts round-trips: Parse → Format → Parse yields the same Line. The
// seeds include the reject cases Parse enforces plus a valid line.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"WEAVE|1|1|unix|/tmp/m.sock",
		"WEAVE|1|3|npipe|\\\\.\\pipe\\weave-m",
		"",
		"WEAVE",
		"WEAVE|1|1|unix", // too few fields
		"WEAVE|9|1|unix|/tmp/m.sock",
		"WEAVE|1|0|unix|/tmp/m.sock", // protocol 0
		"WEAVE|1|1|udp|/tmp/m.sock",  // unknown network
		"WEAVE|1|1|unix|",            // empty addr
		"NOPE|1|1|unix|/tmp/m.sock",
		"WEAVE|abc|1|unix|/tmp/m.sock",
		"WEAVE|1|abc|unix|/tmp/m.sock",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		line, err := Parse(s)
		if err != nil {
			return // rejects are fine; we only care that it never panics
		}
		// Accepted: the rendered form must parse back to an equal Line.
		reparsed, err := Parse(line.Format())
		if err != nil {
			t.Fatalf("Format of an accepted line failed to re-Parse: %q -> %q: %v",
				s, line.Format(), err)
		}
		if reparsed != line {
			t.Fatalf("round-trip changed the line: %+v -> %q -> %+v", line, line.Format(), reparsed)
		}
	})
}
