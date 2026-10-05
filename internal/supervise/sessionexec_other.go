//go:build !darwin

package supervise

import (
	"fmt"
	"io"
)

// sessionExec exists only for macOS: Linux and Windows switch identity in the
// launch itself.
func sessionExec(_ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "weave-agent: "+SessionExecCommand+" is macOS-only")
	return 2
}
