//go:build !windows

package certtrust

// Trust is Windows-only.
func Trust(Location, *Certificate) error { return ErrUnsupported }

// Untrust is Windows-only.
func Untrust(Location, string) error { return ErrUnsupported }

// Trusted is Windows-only.
func Trusted(Location, string) (map[string]bool, error) { return nil, ErrUnsupported }
