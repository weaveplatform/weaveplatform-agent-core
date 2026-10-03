package handshake

import (
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

func TestLineRoundTrip(t *testing.T) {
	l := Line{Protocol: 3, Network: "unix", Addr: "/var/run/weave/weave-linux-presence.sock"}
	got, err := Parse(l.Format())
	if err != nil {
		t.Fatal(err)
	}
	if got != l {
		t.Fatalf("round trip: got %+v want %+v", got, l)
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		"",
		"WEAVE|1|1|unix",
		"NOPE|1|1|unix|/a",
		"WEAVE|2|1|unix|/a",
		"WEAVE|1|0|unix|/a",
		"WEAVE|1|1|tcp|127.0.0.1:1",
		"WEAVE|1|1|unix|",
	}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted, want error", s)
		}
	}
}

func TestWindow(t *testing.T) {
	w, err := ParseWindow("2", "3")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[uint32]bool{1: false, 2: true, 3: true, 4: false} {
		if w.Contains(p) != want {
			t.Errorf("Contains(%d) = %v, want %v", p, !want, want)
		}
	}
	if _, err := ParseWindow("0", "3"); err == nil {
		t.Error("window min 0 accepted")
	}
	if _, err := ParseWindow("3", "2"); err == nil {
		t.Error("inverted window accepted")
	}
}

// A module built against an SDK older than v0.3 prints "winpipe" where current
// ones print "npipe". Those are protocol-1 modules, which core promises to run,
// so the rename must not lock them out.
//
// This broke on Windows only — the unix token never changed, so every unix guest
// kept working and nothing showed it. It surfaced the first time the
// compatibility suite ran on a Windows runner.
func TestParseAcceptsTheLegacyPipeNetworkName(t *testing.T) {
	line, err := Parse(`WEAVE|1|1|winpipe|\\.\pipe\weave-module-x`)
	if err != nil {
		t.Fatalf("a module built against an older SDK was refused: %v", err)
	}
	// Normalised, so nothing downstream has to know two spellings.
	if line.Network != ipc.NetworkPipe {
		t.Errorf("network = %q, want %q", line.Network, ipc.NetworkPipe)
	}
	if line.Addr != `\\.\pipe\weave-module-x` {
		t.Errorf("addr = %q", line.Addr)
	}
}

// The alias is exactly one name, not a general loosening.
func TestParseStillRefusesAnUnknownNetwork(t *testing.T) {
	if _, err := Parse(`WEAVE|1|1|tcp|127.0.0.1:9000`); err == nil {
		t.Fatal("an unknown network was accepted")
	}
}
