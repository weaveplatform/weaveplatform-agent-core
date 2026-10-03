//go:build !dev

package verify

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// Release builds have no core signing identity yet, so a staged core must
// never be promoted, whatever the binary.
func TestReleaseCoreVerifierFailsClosed(t *testing.T) {
	check := Core(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := check(
		"/any/core",
	); err == nil ||
		!strings.Contains(err.Error(), "refusing to promote") {
		t.Fatalf("Core verifier = %v", err)
	}
}

func TestNewReturnsThePlatformVerifier(t *testing.T) {
	if New(slog.New(slog.NewTextHandler(io.Discard, nil))) == nil {
		t.Fatal("New returned nil")
	}
}
