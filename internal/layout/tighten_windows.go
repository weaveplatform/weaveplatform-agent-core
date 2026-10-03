package layout

// tightenDir is a no-op on Windows: directory access is governed by ACLs,
// not Unix mode bits (Go's os.Chmod only toggles the read-only attribute).
// The installer sets a protected SYSTEM+Administrators ACL on the state root
// (winsvc.RestrictDir), and everything core creates below it inherits that.
func tightenDir(_ string) error { return nil }
