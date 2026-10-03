package platform

import (
	"os"
	"syscall"
)

func fill(info *Info) {
	if hn, err := os.Hostname(); err == nil {
		info.Hostname = hn
	}
	// The go-bindings-macosplatform library deliberately wraps no sysctl;
	// stdlib syscall.Sysctl is the established pattern (guestweave-macos
	// internal/platform does the same).
	if v, err := syscall.Sysctl("kern.osproductversion"); err == nil {
		info.Version = v
	}
	if v, err := syscall.Sysctl("kern.osversion"); err == nil {
		info.Build = v
	}
}

// Paths returns the platform filesystem contract on macOS.
func Paths() PathSet {
	return PathSet{
		StateDir:   "/Library/Application Support/Weave",
		LogDir:     "/Library/Logs/Weave",
		RunDir:     "/var/run/weave",
		StagingDir: "/Library/Application Support/Weave/staging",
	}
}
