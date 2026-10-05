//go:build !darwin

package supervise

import (
	"bytes"
	"strings"
	"testing"
)

// The session-exec mode is macOS's alone; elsewhere it refuses.
func TestSessionExecIsMacOSOnly(t *testing.T) {
	var out bytes.Buffer
	if code := SessionExec([]string{"501", "20", "20", "/bin/true"}, &out); code != 2 ||
		!strings.Contains(out.String(), "macOS-only") {
		t.Fatalf("exit %d: %q", code, out.String())
	}
}
