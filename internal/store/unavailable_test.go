package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

func TestUnavailableRefusesEverything(t *testing.T) {
	cause := errors.New("sealed elsewhere")
	u := Unavailable{Err: cause}
	ctx := context.Background()
	_, _, getErr := u.Get(ctx, "m", "k")
	_, listErr := u.List(ctx, "m", "")
	for _, err := range []error{getErr, u.Put(ctx, "m", "k", nil), u.Delete(ctx, "m", "k"), listErr} {
		if !errors.Is(err, werror.ErrUnavailable) || !errors.Is(err, cause) {
			t.Fatalf("err = %v", err)
		}
	}
}

// A store.db kept after its store.key is gone opens under a fresh key, and
// every old value then reads as ErrUndecryptable — the sentinel core keys its
// degraded start on.
func TestValueUnderAnotherKey(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	if err := s.Put(context.Background(), "m", "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Remove(filepath.Join(dir, "store.key")); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, dir)
	defer s.Close()
	if _, _, err := s.Get(context.Background(), "m", "k"); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("Get = %v", err)
	}
}
