// Package wlog constructs the platform's loggers. Everything logs through
// log/slog; wlog owns handler construction so format and level control are
// uniform across core, modules and tools.
//
// A module's logger writes JSON to stderr until Init, after which the SDK
// runtime swaps in a handler that streams records to core's LogService with
// stderr as the fallback.
package wlog

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a JSON slog.Logger writing to w at the given level, with the
// component name attached to every record.
func New(w io.Writer, level slog.Level, component string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", component)
}

// Default returns a stderr JSON logger for the named component, honouring
// WEAVE_LOG_LEVEL (debug, info, warn, error; default info).
func Default(component string) *slog.Logger {
	return New(os.Stderr, LevelFromEnv(), component)
}

// LevelFromEnv reads WEAVE_LOG_LEVEL. Unknown or empty means Info.
func LevelFromEnv() slog.Level {
	switch strings.ToLower(os.Getenv("WEAVE_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
