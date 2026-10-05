//go:build !linux && !darwin && !windows

package core

import (
	"context"
	"log/slog"
)

// watchModules has no watcher here yet: SIGHUP (where there is one),
// ControlService.Reload and the periodic rescan cover these platforms.
func watchModules(context.Context, *slog.Logger, string, func()) {}
