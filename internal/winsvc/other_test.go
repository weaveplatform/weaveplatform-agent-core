//go:build !windows

package winsvc

import (
	"context"
	"errors"
	"testing"
)

func TestStubsOffWindows(t *testing.T) {
	if _, err := NewManager(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewManager = %v", err)
	}
	if svc, err := IsService(); svc || err != nil {
		t.Fatalf("IsService = %v, %v", svc, err)
	}
	if err := Run(func(context.Context) error { return nil }); !errors.Is(err, ErrNotService) {
		t.Fatalf("Run = %v", err)
	}
	if err := RestrictDir(t.TempDir()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RestrictDir = %v", err)
	}
}
