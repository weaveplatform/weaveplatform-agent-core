package store

import (
	"context"
	"fmt"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

// Unavailable stands in for a store core could not open. Every call fails
// with werror.ErrUnavailable and Err, so whatever depends on the store —
// module key/values, the offline queue, the manifest anti-rollback mark —
// refuses plainly instead of acting on a store that is not there.
type Unavailable struct {
	Err error
}

func (u Unavailable) fail(op string) error {
	return fmt.Errorf("store: %s: %w: %w", op, werror.ErrUnavailable, u.Err)
}

// Get implements hostserv.StoreBackend.
func (u Unavailable) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, u.fail("get")
}

// Put implements hostserv.StoreBackend.
func (u Unavailable) Put(context.Context, string, string, []byte) error {
	return u.fail("put")
}

// Delete implements hostserv.StoreBackend.
func (u Unavailable) Delete(context.Context, string, string) error {
	return u.fail("delete")
}

// List implements hostserv.StoreBackend.
func (u Unavailable) List(context.Context, string, string) ([]string, error) {
	return nil, u.fail("list")
}
