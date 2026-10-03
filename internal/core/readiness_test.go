package core

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestSignalReadyWritesMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")
	t.Setenv(envReadyFile, path)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signalReady(log)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("readiness marker not written: %v", err)
	}
}

func TestSignalReadyNoEnvIsNoop(t *testing.T) {
	// No WEAVE_READY_FILE set: signalReady must not panic or write anything.
	t.Setenv(envReadyFile, "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signalReady(log) // nothing to assert beyond "does not blow up"
}
