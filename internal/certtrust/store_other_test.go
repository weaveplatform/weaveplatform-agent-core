//go:build !windows

package certtrust

import (
	"errors"
	"testing"
)

func TestStoresAreWindowsOnly(t *testing.T) {
	if err := Trust(LocalMachine, &Certificate{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Trust = %v", err)
	}
	if err := Untrust(LocalMachine, shippedThumbprint); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Untrust = %v", err)
	}
	if _, err := Trusted(LocalMachine, shippedThumbprint); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Trusted = %v", err)
	}
}
