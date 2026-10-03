//go:build !windows

package winsvc

import "context"

// NewManager is Windows-only.
func NewManager() (Manager, error) { return nil, ErrUnsupported }

// IsService is always false off Windows.
func IsService() (bool, error) { return false, nil }

// Run is Windows-only; elsewhere no SCM ever started the process.
func Run(func(context.Context) error) error { return ErrNotService }

// RestrictDir is Windows-only; unix tightens with mode bits (layout.Ensure).
func RestrictDir(string) error { return ErrUnsupported }
