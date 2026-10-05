//go:build unix && !darwin

package transport

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// openTTY puts a terminal channel into raw mode. No guest outside macOS
// presents its channel as a terminal; this keeps a test pty, or an operator's
// serial console, from echoing and translating the frames.
func openTTY(f *os.File) (io.ReadWriteCloser, error) {
	if _, err := term.MakeRaw(int(f.Fd())); err != nil {
		return nil, fmt.Errorf("making the terminal raw: %w", err)
	}
	return f, nil
}
