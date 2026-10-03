//go:build !linux && !windows

package transport

import (
	"errors"
	"testing"
)

func TestSocketChannelsUnsupportedHere(t *testing.T) {
	if _, err := listenSocket(
		map[string]string{"kind": "vsock", "port": "2010"},
		quietLog(),
	); !errors.Is(
		err,
		errChannelAttrs,
	) {
		t.Fatalf("listenSocket = %v", err)
	}
}
