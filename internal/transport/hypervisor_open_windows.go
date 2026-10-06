package transport

import (
	"errors"
	"fmt"
	"io"
)

// windowsHypervisorDevices are the paths a Windows guest may present the Weave
// channel on: the vioserial named device, then COM2 as a fallback (they
// enumerate on different schedules).
var windowsHypervisorDevices = []string{
	`\\.\Global\org.weave.agent.0`,
	`\\.\COM2`,
}

// errNoOpenableDevice is a Windows guest on which no candidate channel device
// opened.
var errNoOpenableDevice = errors.New("transport: no openable hypervisor device")

// openDevice opens the probed hypervisor device. The Windows capability probe
// currently records only kind=hvsocket without a path, so fall back to the
// known device candidates. The named device is binary-clean (no tty line
// discipline), so no raw-mode handling is needed. It must be opened
// overlapped: see hypervisor_device_windows.go.
func openDevice(attrs map[string]string) (io.ReadWriteCloser, error) {
	candidates := windowsHypervisorDevices
	if d := attrs["device"]; d != "" {
		candidates = append([]string{d}, candidates...)
	}
	for _, d := range candidates {
		if dev, err := openOverlapped(d); err == nil {
			return dev, nil
		}
	}
	return nil, fmt.Errorf("%w (tried %v)", errNoOpenableDevice, candidates)
}
