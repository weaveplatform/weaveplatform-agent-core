package session

import (
	"errors"
	"os"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
)

func fakeWTS(t *testing.T, id uint32, strs map[remotedesktop.WTS_INFO_CLASS]string, err error) {
	t.Helper()
	origID, origStr := activeConsoleSession, sessionString
	activeConsoleSession = func() uint32 { return id }
	sessionString = func(_ uint32, c remotedesktop.WTS_INFO_CLASS) (string, error) {
		if err != nil {
			return "", err
		}
		return strs[c], nil
	}
	t.Cleanup(func() { activeConsoleSession, sessionString = origID, origStr })
}

func TestWindowsConsoleUser(t *testing.T) {
	fakeWTS(t, 1, map[remotedesktop.WTS_INFO_CLASS]string{
		remotedesktop.WTSUserName: "alice", remotedesktop.WTSDomainName: "CORP",
	}, nil)
	s, ok, err := windowsConsole()
	if err != nil || !ok || s.ID != "1" || s.User != `CORP\alice` {
		t.Fatalf("console = %+v ok=%v err=%v", s, ok, err)
	}

	fakeWTS(t, 3, map[remotedesktop.WTS_INFO_CLASS]string{remotedesktop.WTSUserName: "bob"}, nil)
	if s, ok, _ := windowsConsole(); !ok || s.User != "bob" || s.ID != "3" {
		t.Fatalf("no-domain console = %+v ok=%v", s, ok)
	}
}

func TestWindowsNoConsoleUser(t *testing.T) {
	for _, id := range []uint32{noConsoleSession, 0, 1} {
		fakeWTS(t, id, nil, nil) // session 1 at the logon screen: no user
		if s, ok, err := windowsConsole(); ok || err != nil {
			t.Fatalf("session %d: %+v ok=%v err=%v", id, s, ok, err)
		}
	}
}

func TestWindowsConsoleProbeError(t *testing.T) {
	fakeWTS(t, 1, nil, errors.New("rpc down"))
	if _, ok, err := windowsConsole(); ok || err == nil {
		t.Fatalf("probe error swallowed: ok=%v err=%v", ok, err)
	}
}

// The real WTS query works unprivileged for the caller's own session.
func TestQuerySessionStringReal(t *testing.T) {
	var id uint32
	if err := remotedesktop.ProcessIdToSessionId(uint32(os.Getpid()), &id); err != nil {
		t.Fatalf("ProcessIdToSessionId: %v", err)
	}
	user, err := querySessionString(id, remotedesktop.WTSUserName)
	if err != nil {
		t.Fatalf("own session %d user: %v", id, err)
	}
	t.Logf("session %d user %q", id, user)
	if _, err := querySessionString(0xFFFFFFFE, remotedesktop.WTSUserName); err == nil {
		t.Fatal("query of a nonexistent session succeeded")
	}
	if utf16PtrToString(nil) != "" {
		t.Fatal("nil PWSTR is not empty")
	}
}
