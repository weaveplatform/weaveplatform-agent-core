// Command testmodule is the supervisor's integration-test module. It stays
// healthy by default; TESTMOD_EXIT_AFTER_MS makes it crash after start so
// tests can exercise the restart path and the breaker quickly. Config can
// also make it report degraded/unhealthy, refuse Start, fail Stop, or write
// to stdout after the handshake.
//
// It speaks the module protocol directly through core's own protocol
// packages rather than the sdk's module runtime: core must not depend on the
// module-side library, even in tests. What it implements is exactly what the
// supervisor tests drive — the handshake line, ModuleService, the token on
// host calls, the push-watchdog ping loop, and exit when core goes away.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

const (
	moduleID = "testmod"
	protocol = 1
)

type config struct {
	CrashAfterMS int    `json:"crash_after_ms"`
	Health       string `json:"health"`
	FailStart    bool   `json:"fail_start"`
	FailStop     bool   `json:"fail_stop"`
	Stdout       string `json:"stdout"`
}

type server struct {
	agentv1.UnimplementedModuleServiceServer

	hostAddr, token string
	exit            chan struct{}

	mu       sync.Mutex
	cfg      config
	host     *grpc.ClientConn
	watchdog time.Duration
	stopPing context.CancelFunc
}

func (s *server) Init(_ context.Context, req *agentv1.InitRequest) (*agentv1.InitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetModuleId() != moduleID {
		return nil, status.Errorf(codes.FailedPrecondition, "module identity mismatch: core says %q", req.GetModuleId())
	}
	if doc := req.GetConfig(); len(doc) > 0 {
		if err := json.Unmarshal(doc, &s.cfg); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "module config: %v", err)
		}
	}
	conn, err := dialHost(s.hostAddr, s.token)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "connecting host services: %v", err)
	}
	s.host = conn
	s.watchdog = time.Duration(req.GetWatchdogIntervalSeconds()) * time.Second
	go s.exitWhenHostLost(conn)
	return &agentv1.InitResponse{Requires: []*agentv1.Capability{{Name: "platform.osinfo"}}}, nil
}

// dialHost connects to core's host services, presenting the handshake token
// on every call — core refuses a host call without it.
func dialHost(addr, token string) (*grpc.ClientConn, error) {
	withToken := func(ctx context.Context) context.Context {
		return metadata.AppendToOutgoingContext(ctx, handshake.TokenMetadataKey, token)
	}
	return ipc.GRPCClient(ipc.Network(), addr,
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(withToken(ctx), method, req, reply, cc, opts...)
		}),
		grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc,
			cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return streamer(withToken(ctx), desc, cc, method, opts...)
		}))
}

// exitWhenHostLost is the orphan-death rule every module follows: on a
// platform without Pdeathsig, a module whose core has gone must not linger.
func (s *server) exitWhenHostLost(conn *grpc.ClientConn) {
	for {
		state := conn.GetState()
		if state == connectivity.Shutdown || state == connectivity.TransientFailure {
			s.signalExit()
			return
		}
		conn.Connect()
		conn.WaitForStateChange(context.Background(), state)
	}
}

func (s *server) Start(context.Context, *agentv1.StartRequest) (*agentv1.StartResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.FailStart {
		return nil, status.Error(codes.Internal, "module start: configured to refuse start")
	}
	if s.cfg.Stdout != "" {
		fmt.Println(s.cfg.Stdout)
	}
	crash := s.cfg.CrashAfterMS
	if ms, err := strconv.Atoi(os.Getenv("TESTMOD_EXIT_AFTER_MS")); err == nil && ms > 0 {
		crash = ms
	}
	if crash > 0 {
		go func() {
			time.Sleep(time.Duration(crash) * time.Millisecond)
			os.Exit(1)
		}()
	}
	if s.watchdog > 0 && s.stopPing == nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.stopPing = cancel
		go ping(ctx, agentv1.NewWatchdogServiceClient(s.host), s.watchdog)
	}
	return &agentv1.StartResponse{}, nil
}

// ping holds one WatchdogService.Notify stream open and sends on every tick,
// reopening it on the next tick if a send fails.
func ping(ctx context.Context, client agentv1.WatchdogServiceClient, every time.Duration) {
	var (
		stream agentv1.WatchdogService_NotifyClient
		seq    uint64
	)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if stream == nil {
				st, err := client.Notify(ctx)
				if err != nil {
					continue
				}
				stream = st
			}
			seq++
			if err := stream.Send(&agentv1.WatchdogPing{Sequence: seq}); err != nil {
				stream = nil
			}
		}
	}
}

func (s *server) Stop(context.Context, *agentv1.StopRequest) (*agentv1.StopResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopPing != nil {
		s.stopPing()
		s.stopPing = nil
	}
	if s.cfg.FailStop {
		return nil, status.Error(codes.Internal, "module stop: configured to fail stop")
	}
	return &agentv1.StopResponse{}, nil
}

func (s *server) Health(context.Context, *agentv1.HealthRequest) (*agentv1.HealthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := &agentv1.Health{Status: agentv1.Health_STATUS_HEALTHY}
	switch s.cfg.Health {
	case "degraded":
		h = &agentv1.Health{Status: agentv1.Health_STATUS_DEGRADED, Reason: "configured"}
	case "unhealthy":
		h = &agentv1.Health{Status: agentv1.Health_STATUS_UNHEALTHY, Reason: "configured"}
	}
	return &agentv1.HealthResponse{Health: h}, nil
}

func (s *server) Shutdown(context.Context, *agentv1.ShutdownRequest) (*agentv1.ShutdownResponse, error) {
	s.signalExit()
	return &agentv1.ShutdownResponse{}, nil
}

func (s *server) signalExit() {
	select {
	case s.exit <- struct{}{}:
	default:
	}
}

func main() {
	window, err := handshake.ParseWindow(os.Getenv(handshake.EnvProtocolMin), os.Getenv(handshake.EnvProtocolMax))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !window.Contains(protocol) {
		fmt.Fprintf(os.Stderr, "protocol %d outside window [%d,%d]\n", protocol, window.Min, window.Max)
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
	srv := &server{
		hostAddr: os.Getenv(handshake.EnvHostAddr),
		token:    os.Getenv(handshake.EnvToken),
		exit:     make(chan struct{}, 1),
	}
	g := grpc.NewServer()
	agentv1.RegisterModuleServiceServer(g, srv)
	go g.Serve(lis)

	// Exactly one line on stdout before anything else: it is the handshake.
	fmt.Println(handshake.Line{Protocol: protocol, Network: ipc.Network(), Addr: addr}.Format())

	<-srv.exit
	g.GracefulStop()
}
