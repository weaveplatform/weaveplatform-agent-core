// Package controlsock serves ControlService: the one endpoint for weavectl
// and, later, the portal. Access control is the socket itself: it is 0600
// root, inside a RunDir others can traverse but not list, and every
// connection's peer uid must be root or core's own.
package controlsock

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/lifecycle"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/version"
)

// Server implements ControlService over the supervisor's state.
type Server struct {
	controlv1.UnimplementedControlServiceServer

	Log        *slog.Logger
	Supervisor *supervise.Supervisor
	Lifecycle  *lifecycle.Manager
	Window     handshake.Window
	// Identity answers WhoAmI/Enrolled for Status.
	Identity interface {
		WhoAmI(ctx context.Context) (string, bool, string)
		Enrolled() bool
	}
	StartedAt time.Time

	grpcServer *grpc.Server
}

// Serve listens on addr until ctx ends. The control socket carries no
// token: access is by OS peer credentials — only root/SYSTEM or core's own
// user may drive install/rollback. On Windows that matters because a pipe's
// default ACL would admit everyone.
func (s *Server) Serve(ctx context.Context, addr string) error {
	lis, err := ipc.ListenAuthorized(ctx, addr, controlAuthorizer())
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	s.grpcServer = grpc.NewServer()
	controlv1.RegisterControlServiceServer(s.grpcServer, s)
	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()
	s.Log.Info("control socket up", "addr", addr)
	if err := s.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	return nil
}

// Status implements ControlService.
func (s *Server) Status(
	ctx context.Context,
	_ *controlv1.StatusRequest,
) (*controlv1.StatusResponse, error) {
	deviceID, _, _ := s.Identity.WhoAmI(ctx)
	return &controlv1.StatusResponse{
		CoreVersion:   version.Version,
		Protocol:      &agentv1.ProtocolRange{Min: s.Window.Min, Max: s.Window.Max},
		DeviceId:      deviceID,
		Enrolled:      s.Identity.Enrolled(),
		UptimeSeconds: uint64(time.Since(s.StartedAt).Seconds()),
	}, nil
}

// Modules implements ControlService.
func (s *Server) Modules(
	ctx context.Context,
	_ *controlv1.ModulesRequest,
) (*controlv1.ModulesResponse, error) {
	statuses := s.Supervisor.Statuses()
	out := make([]*controlv1.ModuleStatus, 0, len(statuses))
	for _, st := range statuses {
		ms := &controlv1.ModuleStatus{
			Id:       st.ID,
			Version:  st.Version,
			Protocol: st.Protocol,
			State:    string(st.State),
			Health:   st.Health,
			Restarts: st.Restarts,
			Address:  st.Address,
			SinceMs:  st.Since.UnixMilli(),
		}
		if st.PID > 0 && st.PID <= math.MaxInt32 {
			ms.Pid = int32(st.PID)
		}
		if st.Detail != "" {
			ms.State = string(st.State) + ": " + st.Detail
		}
		out = append(out, ms)
	}
	return &controlv1.ModulesResponse{Modules: out}, nil
}

// Surfaces implements ControlService — the portal's read path.
func (s *Server) Surfaces(
	ctx context.Context,
	_ *controlv1.SurfacesRequest,
) (*controlv1.SurfacesResponse, error) {
	statuses := s.Supervisor.Statuses()
	out := make([]*controlv1.ModuleSurfaces, 0, len(statuses))
	for _, st := range statuses {
		if len(st.Surfaces) == 0 {
			continue
		}
		out = append(out, &controlv1.ModuleSurfaces{ModuleId: st.ID, Surfaces: st.Surfaces})
	}
	return &controlv1.SurfacesResponse{Modules: out}, nil
}

// Install implements ControlService: a local-directory install (dev) or a
// channel install by id/version.
func (s *Server) Install(
	ctx context.Context,
	req *controlv1.InstallRequest,
) (*controlv1.InstallResponse, error) {
	var version string
	var err error
	if req.GetLocalPath() != "" {
		version, err = s.Lifecycle.InstallLocal(ctx, req.GetLocalPath())
	} else {
		version, err = s.Lifecycle.Install(ctx, req.GetModuleId(), req.GetVersion())
	}
	if err != nil {
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &controlv1.InstallResponse{InstalledVersion: version}, nil
}

// Rollback implements ControlService.
func (s *Server) Rollback(
	ctx context.Context,
	req *controlv1.RollbackRequest,
) (*controlv1.RollbackResponse, error) {
	version, err := s.Lifecycle.Rollback(ctx, req.GetModuleId())
	if err != nil {
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &controlv1.RollbackResponse{RolledBackTo: version}, nil
}

// Logs implements ControlService. Lands with the log pipeline.
func (s *Server) Logs(_ *controlv1.LogsRequest, _ controlv1.ControlService_LogsServer) error {
	//nolint:wrapcheck // a gRPC status is the handler's contract
	return status.Error(codes.Unimplemented, "log streaming lands with the log pipeline")
}

// Dial connects a control client to a running core.
func Dial(addr string) (controlv1.ControlServiceClient, *grpc.ClientConn, error) {
	network := ipc.NetworkUnix
	if isWindowsAddr(addr) {
		network = ipc.NetworkPipe
	}
	conn, err := ipc.GRPCClient(network, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("control socket: %w", err)
	}
	return controlv1.NewControlServiceClient(conn), conn, nil
}

func isWindowsAddr(addr string) bool {
	return len(addr) > 4 && addr[:4] == `\\.\`
}
