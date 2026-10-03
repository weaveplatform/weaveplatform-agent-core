// Package platform is the deliberately thin OS seam. It answers three
// questions modules and core both ask: what host is this, where do
// platform files live, and what session am I in. Nothing else.
//
// OS bindings (go-bindings-macosplatform, go-bindings-win32, …) are NOT
// re-exported here: they are syscall and purego surfaces that cannot cross
// a wire, and each module links the bindings it needs directly, at the
// versions the protocol pins.
package platform

import (
	"runtime"
)

// Info describes the host. Fields beyond OS and Arch are filled per-OS.
type Info struct {
	// OS is runtime.GOOS: "darwin", "windows", "linux".
	OS string
	// Arch is runtime.GOARCH: "arm64", "amd64".
	Arch string
	// Version is the OS product version, e.g. "15.5" or "10.0.26100".
	Version string
	// Build is the OS build identifier where the OS has one, e.g. "24F74".
	Build string
	// Hostname as reported by the OS.
	Hostname string
}

// Host returns the host description. Errors probing optional fields leave
// them empty rather than failing: identity of the OS is best-effort data,
// not a launch gate.
func Host() Info {
	info := Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
	fill(&info)
	return info
}
