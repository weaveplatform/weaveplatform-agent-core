package supervise

import (
	"slices"
	"testing"
)

func TestMergeEnv(t *testing.T) {
	got := mergeEnv(
		[]string{"PATH=/bin", "HOME=/root", "A=1", "NOEQUALS"},
		[]string{"HOME"},
		[]string{"HOME=/home/u", "A=2"},
		[]string{"A=3", "B=1"},
	)
	want := []string{"PATH=/bin", "A=3", "NOEQUALS", "HOME=/home/u", "B=1"}
	if !slices.Equal(got, want) {
		t.Fatalf("mergeEnv = %q, want %q", got, want)
	}
}

func TestWeaveEnv(t *testing.T) {
	got := weaveEnv(
		[]string{"PATH=/bin", "WEAVE_LOG_LEVEL=debug", "XWEAVE_=no", "WEAVE_STATE_DIR=/s"},
	)
	if want := []string{"WEAVE_LOG_LEVEL=debug", "WEAVE_STATE_DIR=/s"}; !slices.Equal(got, want) {
		t.Fatalf("weaveEnv = %q", got)
	}
}

func TestEnvBlockRoundTrip(t *testing.T) {
	env := []string{"USERPROFILE=C:\\Users\\ålice", "Path=C:\\Windows", "=C:=C:\\"}
	block := encodeEnvBlock(append(env, "", "BAD=\x00x"))
	if block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatal("block not double-NUL terminated")
	}
	if got := decodeEnvBlock(block); !slices.Equal(got, env) {
		t.Fatalf("round trip = %q, want %q", got, env)
	}
	// An empty environment is still a valid block: two NULs.
	if b := encodeEnvBlock(nil); !slices.Equal(b, []uint16{0, 0}) {
		t.Fatalf("empty block = %v", b)
	}
	if got := decodeEnvBlock([]uint16{0, 0}); len(got) != 0 {
		t.Fatalf("empty decode = %q", got)
	}
	// A block missing its terminator ends at the slice.
	if got := decodeEnvBlock([]uint16{'A', '=', '1', 0, 'B'}); !slices.Equal(got, []string{"A=1"}) {
		t.Fatalf("unterminated decode = %q", got)
	}
}
