//go:build !windows

package provision

import (
	"os"
	"path/filepath"
	"testing"
)

// As root the anchor is made root's; an unprivileged run that believed it was
// root fails the install rather than publish an anchor it could not secure.
func TestSecureAnchorAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an unprivileged run to see the chown refused")
	}
	old := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = old })
	pub, _ := newKey(t)
	anchor := filepath.Join(t.TempDir(), "channel.pub")
	if installed, err := install(anchor, pub); installed || err == nil {
		t.Fatalf("install = %v, %v", installed, err)
	}
	if _, err := os.Lstat(anchor); err == nil {
		t.Fatal("an anchor it could not secure was published")
	}
}
