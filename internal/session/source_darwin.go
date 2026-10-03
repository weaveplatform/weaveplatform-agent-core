package session

import (
	"strconv"

	sc "github.com/deploymenttheory/go-bindings-macosplatform/bindings/frameworks/systemconfiguration"
)

// copyConsoleUser is the OS call, a seam so the decisions around it run
// under test with any answer. present is false when SystemConfiguration
// reports no console user at all.
var copyConsoleUser = func() (name string, uid uint32, present bool) {
	// A NULL store asks configd directly; no session object is needed for
	// a one-shot read of State:/Users/ConsoleUser.
	ref, u, _ := sc.SCDynamicStoreCopyConsoleUser(sc.SCDynamicStoreRef{})
	if ref.IsNil() {
		return "", 0, false
	}
	defer ref.Release()
	// CFString is toll-free bridged to NSString, whose -description is the
	// string itself.
	return ref.Description(), uint32(u), true
}

// Console returns this platform's console-session source:
// SCDynamicStoreCopyConsoleUser, the same answer loginwindow publishes when
// it hands the display to a user.
func Console() Source { return SourceFunc(darwinConsole) }

func darwinConsole() (Session, bool, error) {
	name, uid, present := copyConsoleUser()
	// At the login window the console "user" is loginwindow (or nobody), and
	// during Setup Assistant it is _mbsetupuser — neither is a person whose
	// pasteboard a module should touch. uid 0 is root at the console, which a
	// per-user module must never run as.
	if !present || name == "" || name == "loginwindow" || name == "_mbsetupuser" || uid == 0 {
		return Session{}, false, nil
	}
	return Session{
		ID:   "gui/" + strconv.FormatUint(uint64(uid), 10),
		User: name,
		UID:  uid,
	}, true, nil
}
