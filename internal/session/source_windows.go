package session

import (
	"fmt"
	"strconv"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/remotedesktop"
)

// noConsoleSession is what WTSGetActiveConsoleSessionId returns while the
// console is detached — mid-switch between sessions.
const noConsoleSession = 0xFFFFFFFF

// Seams over the WTS calls, so the decisions around them run under test.
var (
	activeConsoleSession = remotedesktop.WTSGetActiveConsoleSessionId
	sessionString        = querySessionString
)

// Console returns this platform's console-session source: the active
// console session id (fast user switching moves the console between
// sessions; RDP sessions are never it) and the user logged on to it.
func Console() Source { return SourceFunc(windowsConsole) }

func windowsConsole() (Session, bool, error) {
	id := activeConsoleSession()
	// Session 0 is services-only since Vista; it never has a desktop user.
	if id == noConsoleSession || id == 0 {
		return Session{}, false, nil
	}
	user, err := sessionString(id, remotedesktop.WTSUserName)
	if err != nil {
		return Session{}, false, err
	}
	// The console session exists at the logon screen too, with no user in it.
	if user == "" {
		return Session{}, false, nil
	}
	if domain, err := sessionString(id, remotedesktop.WTSDomainName); err == nil && domain != "" {
		user = domain + `\` + user
	}
	return Session{ID: strconv.FormatUint(uint64(id), 10), User: user}, true, nil
}

func querySessionString(id uint32, class remotedesktop.WTS_INFO_CLASS) (string, error) {
	var buf foundation.PWSTR
	var n uint32
	if err := remotedesktop.WTSQuerySessionInformation(
		remotedesktop.WTS_CURRENT_SERVER_HANDLE,
		id,
		class,
		&buf,
		&n,
	); err != nil {
		return "", fmt.Errorf("WTSQuerySessionInformation: %w", err)
	}
	defer remotedesktop.WTSFreeMemory(unsafe.Pointer(buf))
	return utf16PtrToString(buf), nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for ptr := unsafe.Pointer(p); ; ptr = unsafe.Add(ptr, 2) {
		c := *(*uint16)(ptr)
		if c == 0 {
			break
		}
		s = append(s, c)
	}
	return string(utf16.Decode(s))
}
