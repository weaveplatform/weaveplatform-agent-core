package session

import "testing"

func fakeConsoleUser(t *testing.T, name string, uid uint32, present bool) {
	t.Helper()
	orig := copyConsoleUser
	copyConsoleUser = func() (string, uint32, bool) { return name, uid, present }
	t.Cleanup(func() { copyConsoleUser = orig })
}

func TestDarwinConsoleUser(t *testing.T) {
	fakeConsoleUser(t, "alice", 501, true)
	s, ok, err := darwinConsole()
	if err != nil || !ok || s.ID != "gui/501" || s.User != "alice" || s.UID != 501 ||
		len(s.Env) != 0 {
		t.Fatalf("console = %+v ok=%v err=%v", s, ok, err)
	}
}

func TestDarwinNoConsoleUser(t *testing.T) {
	cases := []struct {
		name    string
		uid     uint32
		present bool
	}{
		{"", 0, false},
		{"", 501, true},
		{"loginwindow", 0, true},
		{"_mbsetupuser", 248, true},
		{"root", 0, true},
	}
	for _, c := range cases {
		fakeConsoleUser(t, c.name, c.uid, c.present)
		if s, ok, err := darwinConsole(); ok || err != nil {
			t.Fatalf("%+v: console = %+v ok=%v err=%v", c, s, ok, err)
		}
	}
}
