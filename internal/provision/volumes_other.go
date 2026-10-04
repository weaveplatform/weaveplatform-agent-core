//go:build !darwin && !linux && !windows

package provision

// platformVolumes finds nothing where there is no lookup for this platform.
func platformVolumes() ([]string, error) { return nil, nil }
