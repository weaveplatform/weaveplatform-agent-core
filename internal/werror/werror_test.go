package werror

import (
	"errors"
	"testing"
)

func TestOpNilStaysNil(t *testing.T) {
	if err := Op("store.get", nil); err != nil {
		t.Fatalf("Op(nil) = %v", err)
	}
}

func TestOpKeepsSentinel(t *testing.T) {
	err := Op("store.get", ErrNotFound)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v does not wrap ErrNotFound", err)
	}
	if got, want := err.Error(), "store.get: not found"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
