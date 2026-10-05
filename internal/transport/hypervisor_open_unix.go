//go:build unix

package transport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/term"
)

// errNoDevice is a device channel whose probe named no device node.
var errNoDevice = errors.New("no hypervisor device in probe attributes")

// openDevice opens the probed hypervisor device node. On macOS the channel is
// a calling-unit tty (/dev/cu.*) whose line discipline would corrupt the frame
// protocol, so it goes through openTTY; a Linux virtio-ports node is a plain
// character device and is left as-is.
func openDevice(attrs map[string]string) (io.ReadWriteCloser, error) {
	dev := attrs["device"]
	if dev == "" {
		return nil, errNoDevice
	}
	f, err := os.OpenFile(dev, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", dev, err)
	}
	if !term.IsTerminal(int(f.Fd())) {
		return f, nil
	}
	rwc, err := openTTY(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("raw mode on %s: %w", dev, err)
	}
	return rwc, nil
}
