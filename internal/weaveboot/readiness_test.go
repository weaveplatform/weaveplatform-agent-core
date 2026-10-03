package weaveboot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkerFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")

	if markerFresh(path) {
		t.Fatal("no marker written yet, markerFresh should be false")
	}
	if err := os.WriteFile(path, []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !markerFresh(path) {
		t.Fatal("marker present, markerFresh should be true")
	}
	// After the pre-launch clear, absence must read as not-ready again.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if markerFresh(path) {
		t.Fatal("marker removed, markerFresh should be false")
	}
}
