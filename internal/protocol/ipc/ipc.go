// Package ipc owns local transport: Unix domain sockets on macOS and
// Linux, named pipes on Windows, behind one Listen/Dial seam so neither
// core nor a module runtime carries per-OS socket code at call sites.
//
// Access control is filesystem/ACL-based: sockets live in mode-0700
// directories owned by the spawning side; Windows pipes carry an SDDL.
// There is no TLS on these links — core verified the binary before exec,
// and the OS authenticates the peer.
package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Networks understood by this package. These are the values that appear in
// the handshake line.
const (
	NetworkUnix = "unix"
	NetworkPipe = "npipe"
)

// ErrUnsupportedNetwork reports a dial for a network this platform's
// transport does not speak.
var ErrUnsupportedNetwork = errors.New("ipc: network not supported on this platform")

// Listen creates a listener at addr for the platform's network:
// a socket path on unix, a \\.\pipe\ name on Windows.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	return listen(ctx, addr)
}

// Network returns the network name this platform's Listen produces,
// for embedding in the handshake line.
func Network() string {
	return network
}

// Dial connects to a peer's listener. The context bounds the dial only.
func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return dial(ctx, network, addr)
}

// GRPCClient returns a gRPC client connection over the local transport.
// target is the handshake-line address; network selects unix vs npipe.
func GRPCClient(network, addr string, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dial(ctx, network, addr)
		}),
	}, extra...)
	// The target string is decorative once a custom dialer is installed;
	// passthrough avoids any resolver involvement.
	conn, err := grpc.NewClient("passthrough:///"+addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("ipc: grpc client for %s: %w", addr, err)
	}
	return conn, nil
}
