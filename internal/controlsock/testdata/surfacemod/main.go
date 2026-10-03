// Command surfacemod is a control-socket test module that declares one UI
// surface during Init, so the portal read path has something to return.
//
// It speaks the module protocol directly through core's own protocol
// packages, not the sdk's module runtime, and implements only what the
// control-socket tests drive: the handshake line and a ModuleService whose
// Init answer carries the surface. It never calls the host, so it never dials
// it.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

const (
	moduleID = "surfmod"
	protocol = 1
)

type server struct {
	agentv1.UnimplementedModuleServiceServer
	exit chan struct{}
}

func (server) Init(context.Context, *agentv1.InitRequest) (*agentv1.InitResponse, error) {
	return &agentv1.InitResponse{
		Requires: []*agentv1.Capability{{Name: "platform.osinfo"}},
		Surfaces: []*agentv1.Surface{{Id: "panel", Title: "Panel", Kind: "card"}},
	}, nil
}

func (server) Start(context.Context, *agentv1.StartRequest) (*agentv1.StartResponse, error) {
	return &agentv1.StartResponse{}, nil
}

func (server) Stop(context.Context, *agentv1.StopRequest) (*agentv1.StopResponse, error) {
	return &agentv1.StopResponse{}, nil
}

func (server) Health(context.Context, *agentv1.HealthRequest) (*agentv1.HealthResponse, error) {
	return &agentv1.HealthResponse{Health: &agentv1.Health{Status: agentv1.Health_STATUS_HEALTHY}}, nil
}

func (s server) Shutdown(context.Context, *agentv1.ShutdownRequest) (*agentv1.ShutdownResponse, error) {
	select {
	case s.exit <- struct{}{}:
	default:
	}
	return &agentv1.ShutdownResponse{}, nil
}

func main() {
	window, err := handshake.ParseWindow(os.Getenv(handshake.EnvProtocolMin), os.Getenv(handshake.EnvProtocolMax))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !window.Contains(protocol) {
		os.Exit(handshake.ExitProtocolUnsupported)
	}

	addr := filepath.Join(os.Getenv(handshake.EnvSocketDir), moduleID+".sock")
	if runtime.GOOS == "windows" {
		addr = fmt.Sprintf(`\\.\pipe\weave-%s-%d`, moduleID, os.Getpid())
	}
	lis, err := ipc.Listen(context.Background(), addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srv := server{exit: make(chan struct{}, 1)}
	g := grpc.NewServer()
	agentv1.RegisterModuleServiceServer(g, srv)
	go g.Serve(lis)

	fmt.Println(handshake.Line{Protocol: protocol, Network: ipc.Network(), Addr: addr}.Format())

	<-srv.exit
	g.GracefulStop()
}
