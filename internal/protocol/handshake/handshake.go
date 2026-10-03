// Package handshake is the shared vocabulary of the core↔module handshake:
// the environment core sets, the one stdout line the module answers with,
// and the exit code that means "protocol out of window". Both sides import
// this package; neither side imports the other.
//
// The flow (PROTOCOL.md owns the normative text):
//
//	core → module    env: EnvProtocolMin, EnvProtocolMax, EnvToken,
//	                      EnvHostAddr, EnvSocketDir
//	module → core    stdout: WEAVE|1|<protocol>|<network>|<addr>
//	core → module    gRPC ModuleService.Init on <addr>
//	module → core    gRPC dial EnvHostAddr presenting the token
package handshake

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

// Environment variables core sets before exec'ing a module.
const (
	// EnvProtocolMin and EnvProtocolMax advertise core's accepted window.
	EnvProtocolMin = "WEAVE_PROTOCOL_MIN"
	EnvProtocolMax = "WEAVE_PROTOCOL_MAX"
	// EnvToken is the one-time token the module presents when dialing the
	// host address; core binds the connection to the module's identity.
	EnvToken = "WEAVE_HANDSHAKE_TOKEN"
	// EnvHostAddr is where core serves this module's host services.
	EnvHostAddr = "WEAVE_HOST_ADDR"
	// EnvSocketDir is the core-owned directory the module's own socket
	// must be created in (ignored for Windows named pipes).
	EnvSocketDir = "WEAVE_SOCKET_DIR"
	// Config is NOT an env var: it rides InitRequest.Config on the wire.
)

// legacyNetworkPipe is the protocol-1 SDK's spelling of ipc.NetworkPipe below
// v0.3. Modules built against those releases print it, and they are protocol-1
// modules that core runs — so Parse accepts it and normalises. Nothing writes it.
const legacyNetworkPipe = "winpipe"

// Errors Parse and ParseWindow wrap. Each message carries the offending value
// after the sentinel's text.
var (
	ErrMalformedLine  = errors.New("handshake: malformed line")
	ErrLineVersion    = errors.New("handshake: unsupported line version")
	ErrBadProtocol    = errors.New("handshake: bad protocol")
	ErrUnknownNetwork = errors.New("handshake: unknown network")
	ErrEmptyAddress   = errors.New("handshake: empty address")
	ErrBadWindowBound = errors.New("handshake: bad")
	ErrInvalidWindow  = errors.New("handshake: invalid window")
)

// LineVersion is the handshake format version — the leading field of the
// stdout line, distinct from the protocol integer that follows it.
const LineVersion = 1

// ExitProtocolUnsupported (EX_CONFIG) is the exit code a module uses when
// its protocol falls outside the advertised window. Core records
// "protocol unsupported" and does not restart — refusal is clean, never a
// crash loop.
const ExitProtocolUnsupported = 78

// TokenMetadataKey is the gRPC metadata key the module presents the
// one-time token under when dialing the host address.
const TokenMetadataKey = "weave-handshake-token"

// Line is the module's one-line stdout answer.
type Line struct {
	// Protocol the module speaks (already validated against the window).
	Protocol uint32
	// Network is "unix" or "npipe".
	Network string
	// Addr is the socket path or pipe name the module is listening on.
	Addr string
}

// Format renders the line without a trailing newline.
func (l Line) Format() string {
	return fmt.Sprintf("WEAVE|%d|%d|%s|%s", LineVersion, l.Protocol, l.Network, l.Addr)
}

// Parse parses a module's stdout line.
func Parse(s string) (Line, error) {
	parts := strings.Split(strings.TrimSpace(s), "|")
	if len(parts) != 5 || parts[0] != "WEAVE" {
		return Line{}, fmt.Errorf("%w %q", ErrMalformedLine, s)
	}
	v, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || v != LineVersion {
		return Line{}, fmt.Errorf("%w %q", ErrLineVersion, parts[1])
	}
	p, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || p == 0 {
		return Line{}, fmt.Errorf("%w %q", ErrBadProtocol, parts[2])
	}
	network := parts[3]
	// "winpipe" is what this field was called before the rename to "npipe", and
	// it is still what a module built against an SDK older than v0.3 prints.
	// Refusing it broke the protocol-1 promise on Windows only — the unix token
	// never changed, so every unix guest kept working and nothing showed it.
	// Accept the old spelling and normalise; the alias costs one comparison and
	// buys compatibility with every module already built.
	if network == legacyNetworkPipe {
		network = ipc.NetworkPipe
	}
	if network != ipc.NetworkUnix && network != ipc.NetworkPipe {
		return Line{}, fmt.Errorf("%w %q", ErrUnknownNetwork, parts[3])
	}
	if parts[4] == "" {
		return Line{}, ErrEmptyAddress
	}
	return Line{Protocol: uint32(p), Network: network, Addr: parts[4]}, nil
}

// Window is core's advertised protocol range as read from (or written to)
// the environment.
type Window struct {
	Min, Max uint32
}

// Contains reports whether p falls inside the window.
func (w Window) Contains(p uint32) bool { return p >= w.Min && p <= w.Max }

// ParseWindow reads the two env values (as strings) into a Window.
func ParseWindow(min, max string) (Window, error) {
	lo, err := strconv.ParseUint(min, 10, 32)
	if err != nil {
		return Window{}, fmt.Errorf("%w %s %q", ErrBadWindowBound, EnvProtocolMin, min)
	}
	hi, err := strconv.ParseUint(max, 10, 32)
	if err != nil {
		return Window{}, fmt.Errorf("%w %s %q", ErrBadWindowBound, EnvProtocolMax, max)
	}
	if lo == 0 || hi < lo {
		return Window{}, fmt.Errorf("%w [%d,%d]", ErrInvalidWindow, lo, hi)
	}
	return Window{Min: uint32(lo), Max: uint32(hi)}, nil
}
