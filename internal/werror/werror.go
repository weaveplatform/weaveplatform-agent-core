// Package werror carries the platform's error conventions: sentinel errors
// for conditions callers branch on, and wrapping helpers that keep module
// and operation context attached. Named werror, not errors, so import sites
// never shadow the standard library.
package werror

import (
	"errors"
	"fmt"
)

// Sentinels callers are expected to test with errors.Is.
var (
	// ErrNotFound: the named thing does not exist (store key, module id).
	ErrNotFound = errors.New("not found")
	// ErrUnavailable: the dependency exists but cannot serve right now;
	// retrying is reasonable.
	ErrUnavailable = errors.New("unavailable")
	// ErrProtocol: the peer spoke a protocol outside the accepted window,
	// or violated the handshake. Retrying will not help.
	ErrProtocol = errors.New("protocol violation")
	// ErrDenied: the caller is authenticated but not permitted.
	ErrDenied = errors.New("denied")
)

// Op wraps err with an operation label: werror.Op("store.get", err).
// Returns nil when err is nil so call sites can wrap unconditionally.
func Op(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}
