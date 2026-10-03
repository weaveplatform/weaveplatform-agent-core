package capability

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Channel kinds an operator can name with -channel / WEAVE_CHANNEL.
const (
	// ChannelAuto is today's default: look for the named virtio-serial port
	// (and, on Windows, the Hyper-V guest marker).
	ChannelAuto = "auto"
	// ChannelVirtioSerial forces the device-node probe.
	ChannelVirtioSerial = "virtio-serial"
	// ChannelVsock listens on an AF_VSOCK port (Linux guests).
	ChannelVsock = "vsock"
	// ChannelHvSocket listens on an HvSocket service (Windows guests).
	ChannelHvSocket = "hvsocket"
	// ChannelUnix listens on a Unix socket at an absolute path: the channel
	// into a container, whose host bind-mounts the socket's directory and
	// dials it. Every OS (Windows 10 1803+ has AF_UNIX).
	ChannelUnix = "unix"
	// ChannelNone claims no channel at all. It is what a configuration that
	// failed to parse becomes, never something an operator writes.
	ChannelNone = "none"
)

// ErrChannelConfig marks a -channel value core cannot honour.
var ErrChannelConfig = errors.New("invalid hypervisor channel configuration")

// Channel is the parsed hypervisor-channel configuration.
//
// Socket channels are only ever configured, never inferred: a socket family
// being available says nothing about whether the host is listening on it (see
// probe_linux.go for what inferring it from /dev/vsock once cost).
type Channel struct {
	Kind string
	// Port is the vsock port for socket kinds; on Windows it names the
	// HvSocket service through the vsock template GUID.
	Port uint32
	// Path is the socket path of a unix channel.
	Path string
}

// ParseChannel parses a -channel value for this OS.
func ParseChannel(s string) (Channel, error) { return parseChannel(s, runtime.GOOS) }

func parseChannel(s, goos string) (Channel, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", ChannelAuto:
		return Channel{Kind: ChannelAuto}, nil
	case ChannelVirtioSerial:
		return Channel{Kind: ChannelVirtioSerial}, nil
	}
	kind, portStr, ok := strings.Cut(s, ":")
	if kind == ChannelUnix {
		if !ok || !isAbs(portStr, goos) {
			return Channel{}, fmt.Errorf(
				"%w: %q needs an absolute socket path, e.g. unix:/run/weave/channel.sock",
				ErrChannelConfig,
				s,
			)
		}
		return Channel{Kind: ChannelUnix, Path: portStr}, nil
	}
	var want string
	switch kind {
	case ChannelVsock:
		want = "linux"
	case ChannelHvSocket:
		want = "windows"
	default:
		return Channel{}, fmt.Errorf(
			"%w: %q (want auto, virtio-serial, vsock:<port>, hvsocket:<port> or unix:<path>)",
			ErrChannelConfig,
			s,
		)
	}
	if goos != want {
		return Channel{}, fmt.Errorf(
			"%w: %s is only supported on %s, not %s",
			ErrChannelConfig,
			kind,
			want,
			goos,
		)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	// Port 0 is not a port anyone listens on, and -1U is VMADDR_PORT_ANY:
	// binding it would pick a port the host has no way of knowing.
	if !ok || err != nil || port == 0 || port == 0xFFFFFFFF {
		return Channel{}, fmt.Errorf("%w: %q needs a port, e.g. %s:2010", ErrChannelConfig, s, kind)
	}
	return Channel{Kind: kind, Port: uint32(port)}, nil
}

// isAbs judges an absolute path by the rules of goos, not the OS running the
// parse, so the parser is testable for every target.
func isAbs(p, goos string) bool {
	if goos == "windows" {
		return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') ||
			strings.HasPrefix(p, `\\`)
	}
	return strings.HasPrefix(p, "/")
}

// String renders the channel the way it was configured.
func (c Channel) String() string {
	if c.Kind == ChannelUnix {
		return c.Kind + ":" + c.Path
	}
	if c.Port != 0 {
		return c.Kind + ":" + strconv.FormatUint(uint64(c.Port), 10)
	}
	return c.Kind
}

// socketAttrs is the capability a configured socket channel claims. The
// transport reads the kind and port back out of it.
func (c Channel) socketAttrs() map[string]string { //nolint:unused // used by the linux and windows probes
	return map[string]string{"kind": c.Kind, "port": strconv.FormatUint(uint64(c.Port), 10)}
}

// unixAttrs is the capability a configured unix channel claims.
func (c Channel) unixAttrs() map[string]string {
	return map[string]string{"kind": ChannelUnix, "path": c.Path}
}
