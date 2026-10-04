package layout

import "os"

// setDirMode is a no-op on Windows: directory access is governed by ACLs,
// not Unix mode bits (Go's os.Chmod only toggles the read-only attribute).
// The installer sets a protected SYSTEM+Administrators ACL on the state root
// (winsvc.RestrictDir), and everything core creates below it inherits that.
// Windows needs no traversal grant either: a module's image is opened with
// core's access (CreateProcessAsUser), and its host endpoint is a pipe.
func setDirMode(_ string, _ os.FileMode) error { return nil }
