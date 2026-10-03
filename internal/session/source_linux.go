package session

// Console returns this platform's console-session source: logind's state
// files.
func Console() Source { return Logind{} }
