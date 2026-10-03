package session

import "testing"

func TestLinuxConsoleIsLogind(t *testing.T) {
	if _, ok := Console().(Logind); !ok {
		t.Fatalf("Console() = %T, want Logind", Console())
	}
}
