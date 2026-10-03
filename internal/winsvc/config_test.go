package winsvc

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCommandLineQuoting(t *testing.T) {
	c := Config{
		BinaryPath: `C:\Program Files\Weave\weaveboot.exe`,
		Args: []string{
			"--",
			"--modules-dir",
			`C:\Program Files\Weave\modules`,
			"plain",
			"",
			`say "hi"`,
			`trail\ `,
		},
	}
	want := `"C:\Program Files\Weave\weaveboot.exe" -- --modules-dir "C:\Program Files\Weave\modules" plain "" "say \"hi\"" "trail\ "`
	if got := c.CommandLine(); got != want {
		t.Fatalf("CommandLine()\n got %s\nwant %s", got, want)
	}
	// The program name is quoted even without spaces, and a trailing
	// backslash is doubled so it does not escape the closing quote.
	if got := (Config{BinaryPath: `C:\w\`}).CommandLine(); got != `"C:\w\\"` {
		t.Fatalf("got %s", got)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Name: "WeaveAgent", BinaryPath: `C:\w.exe`, Env: []string{"A=1"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"empty name":  {BinaryPath: "x"},
		"slash":       {Name: `a\b`, BinaryPath: "x"},
		"no binary":   {Name: "n"},
		"nul in args": {Name: "n", BinaryPath: "x", Args: []string{"a\x00"}},
		"bad env":     {Name: "n", BinaryPath: "x", Env: []string{"novalue"}},
	} {
		if err := c.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateEnv(t *testing.T) {
	if err := ValidateEnv([]string{"A=1", "B=", "C=x=y"}); err != nil {
		t.Fatal(err)
	}
	for _, env := range [][]string{
		{"=1"}, {"A"}, {"A=\x00"}, {"A=1", "a=2"},
	} {
		if err := ValidateEnv(env); err == nil {
			t.Errorf("%q accepted", env)
		}
	}
}

func TestMultiSZRoundTrip(t *testing.T) {
	in := []string{"WEAVE_CHANNEL_PUB=C:\\ProgramData\\weave\\channel.pub", "Ü=ünïcode", "X="}
	b := EncodeMultiSZ(in)
	// UTF-16LE, each string NUL-terminated, plus the list terminator.
	if b[len(b)-1] != 0 || b[len(b)-2] != 0 || b[len(b)-3] != 0 || b[len(b)-4] != 0 {
		t.Fatalf("missing double terminator: % x", b[len(b)-4:])
	}
	if b[0] != 'W' || b[1] != 0 {
		t.Fatalf("not little-endian UTF-16: % x", b[:2])
	}
	if got := DecodeMultiSZ(b); !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip = %q", got)
	}
	if EncodeMultiSZ(nil) != nil {
		t.Fatal("empty list must encode to nil")
	}
	// Tolerates a writer that leaves off the final terminator.
	trunc := EncodeMultiSZ([]string{"A=1", "B=2"})
	trunc = trunc[:len(trunc)-4]
	if got := DecodeMultiSZ(trunc); !reflect.DeepEqual(got, []string{"A=1", "B=2"}) {
		t.Fatalf("unterminated = %q", got)
	}
	if got := DecodeMultiSZ(nil); got != nil {
		t.Fatalf("empty = %q", got)
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{
		Stopped: "stopped", StartPending: "start-pending", StopPending: "stop-pending",
		Running: "running", ContinuePending: "continue-pending", PausePending: "pause-pending",
		Paused: "paused", 99: "unknown",
	} {
		if s.String() != want {
			t.Errorf("%d = %s", s, s)
		}
	}
}

func TestDefaultsAreSane(t *testing.T) {
	if !strings.HasSuffix(DefaultInstallDir(), "Weave") {
		t.Fatal(DefaultInstallDir())
	}
	t.Setenv("ProgramFiles", "")
	if !strings.HasPrefix(DefaultInstallDir(), `C:\Program Files`) {
		t.Fatal(DefaultInstallDir())
	}
}
