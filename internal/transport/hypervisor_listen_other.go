//go:build !linux && !windows

package transport

import (
	"fmt"
	"log/slog"
	"runtime"
)

func listenSocket(attrs map[string]string, _ *slog.Logger) (connListener, error) {
	return nil, fmt.Errorf(
		"%w: %s channels are not supported on %s",
		errChannelAttrs,
		attrs["kind"],
		runtime.GOOS,
	)
}
