// Package hostserv serves core's host services to modules, one gRPC server
// per module socket. Authorization is two-factor: the connection is bound to
// the module's verified peer credential (the primary gate, set up by the
// supervisor on the socket), and every RPC additionally carries the module's
// handshake token, compared in constant time as a second factor. The
// backends are seams: in-memory today, replaced by the encrypted store, the
// policy pipeline and the real transport as those milestones land.
package hostserv

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/werror"
)

// grpcErr maps a backend error to a gRPC status, translating werror
// sentinels to their wire codes so callers see NotFound/Unavailable/etc.
// rather than everything flattened to Internal. A nil error stays nil.
func grpcErr(err error) error {
	if err == nil {
		return nil
	}
	var code codes.Code
	switch {
	case errors.Is(err, werror.ErrNotFound):
		code = codes.NotFound
	case errors.Is(err, werror.ErrUnavailable):
		code = codes.Unavailable
	case errors.Is(err, werror.ErrDenied):
		code = codes.PermissionDenied
	case errors.Is(err, werror.ErrProtocol):
		code = codes.FailedPrecondition
	default:
		code = codes.Internal
	}
	//nolint:wrapcheck // a gRPC status is the handler's contract
	return status.Error(code, err.Error())
}

// topicAllowed reports whether a requested subscribe pattern is covered by
// the module's declared allow-list. A request is allowed when it exactly
// matches an allowed entry, or when an allowed prefix glob ("a.*") covers
// the request (including a narrower request under that prefix). A bare "*"
// request is only allowed if the module explicitly declared "*".
func topicAllowed(request string, allow []string) bool {
	for _, a := range allow {
		if a == request {
			return true
		}
		if pre, ok := strings.CutSuffix(a, "*"); ok && strings.HasPrefix(request, pre) {
			return true
		}
	}
	return false
}

// StoreBackend persists module key/values. Keys arrive namespaced by
// module id at this seam. ctx bounds the (real, on-disk) operation.
type StoreBackend interface {
	Get(ctx context.Context, module, key string) ([]byte, bool, error)
	Put(ctx context.Context, module, key string, value []byte) error
	Delete(ctx context.Context, module, key string) error
	List(ctx context.Context, module, prefix string) ([]string, error)
}

// PolicyBackend delivers module-scoped policy.
type PolicyBackend interface {
	Get(ctx context.Context, module string) (revision uint64, data []byte, err error)
	// Watch returns a channel that signals on every change until ctx
	// ends.
	Watch(ctx context.Context, module string) <-chan struct{}
}

// IdentityBackend answers identity questions on a module's behalf.
type IdentityBackend interface {
	WhoAmI(ctx context.Context) (deviceID string, ephemeral bool, tenant string)
	Credential(
		ctx context.Context,
		module string,
		scopes []string,
	) (token string, expiresAt int64, granted []string, err error)
}

// TransportBackend routes module messages to peers.
type TransportBackend interface {
	Send(
		ctx context.Context,
		module string,
		peer agentv1.Peer,
		kind string,
		data []byte,
		queueOffline bool,
	) (delivered bool, err error)
	Receive(ctx context.Context, module string) <-chan *agentv1.TransportMessage
}

// RegistryBackend is core's installed-module table; *registry.Registry
// implements it.
type RegistryBackend interface {
	List() (revision uint64, modules []registry.Module)
	Core() registry.Core
	Watch(ctx context.Context) <-chan struct{}
}

// Services aggregates the backends core wires once at startup.
type Services struct {
	Log       *slog.Logger
	Bus       *eventbus.Bus
	Store     StoreBackend
	Policy    PolicyBackend
	Identity  IdentityBackend
	Transport TransportBackend
	// Registry answers RegistryService. Nil answers Unavailable.
	Registry RegistryBackend
	// Watchdog, if set, is called with the module id on every watchdog
	// ping so the supervisor can track liveness. Nil disables the seam.
	Watchdog func(module string)
}

// NewServer builds the per-module gRPC server: all host services, bound to
// the module's identity, gated by its token. channelAddress is the name its
// Transport traffic is routed under on the hypervisor channel (the manifest
// address, or the id); every other service keys on the id. subscribes is the
// module's declared event-topic allow-list (from its manifest).
func (s *Services) NewServer(
	moduleID, channelAddress, token string,
	subscribes []string,
) *grpc.Server {
	srv := grpc.NewServer(tokenGate(token)...)
	agentv1.RegisterStoreServiceServer(srv, &storeServer{s: s, module: moduleID})
	agentv1.RegisterPolicyServiceServer(srv, &policyServer{s: s, module: moduleID})
	agentv1.RegisterEventBusServiceServer(
		srv,
		&eventsServer{s: s, module: moduleID, allow: subscribes},
	)
	agentv1.RegisterIdentityServiceServer(srv, &identityServer{s: s, module: moduleID})
	agentv1.RegisterTransportServiceServer(srv, &transportServer{s: s, module: channelAddress})
	agentv1.RegisterLogServiceServer(srv, &logServer{s: s, module: moduleID})
	agentv1.RegisterWatchdogServiceServer(srv, &watchdogServer{s: s, module: moduleID})
	agentv1.RegisterRegistryServiceServer(srv, &registryServer{s: s})
	return srv
}

func tokenGate(token string) []grpc.ServerOption {
	check := func(ctx context.Context) error {
		md, _ := metadata.FromIncomingContext(ctx)
		vals := md.Get(handshake.TokenMetadataKey)
		if len(vals) != 1 || subtle.ConstantTimeCompare([]byte(vals[0]), []byte(token)) != 1 {
			return status.Error(codes.Unauthenticated, "missing or wrong handshake token")
		}
		return nil
	}
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo,
			h grpc.UnaryHandler,
		) (any, error) {
			if err := check(ctx); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo,
			h grpc.StreamHandler,
		) error {
			if err := check(ss.Context()); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	}
}

// --- Store ---

type storeServer struct {
	agentv1.UnimplementedStoreServiceServer
	s      *Services
	module string
}

func (v *storeServer) Get(
	ctx context.Context,
	req *agentv1.StoreGetRequest,
) (*agentv1.StoreGetResponse, error) {
	val, ok, err := v.s.Store.Get(ctx, v.module, req.GetKey())
	if err != nil {
		return nil, grpcErr(err)
	}
	return &agentv1.StoreGetResponse{Value: val, Found: ok}, nil
}

func (v *storeServer) Put(
	ctx context.Context,
	req *agentv1.StorePutRequest,
) (*agentv1.StorePutResponse, error) {
	if err := v.s.Store.Put(ctx, v.module, req.GetKey(), req.GetValue()); err != nil {
		return nil, grpcErr(err)
	}
	return &agentv1.StorePutResponse{}, nil
}

func (v *storeServer) Delete(
	ctx context.Context,
	req *agentv1.StoreDeleteRequest,
) (*agentv1.StoreDeleteResponse, error) {
	if err := v.s.Store.Delete(ctx, v.module, req.GetKey()); err != nil {
		return nil, grpcErr(err)
	}
	return &agentv1.StoreDeleteResponse{}, nil
}

func (v *storeServer) List(
	ctx context.Context,
	req *agentv1.StoreListRequest,
) (*agentv1.StoreListResponse, error) {
	keys, err := v.s.Store.List(ctx, v.module, req.GetPrefix())
	if err != nil {
		return nil, grpcErr(err)
	}
	return &agentv1.StoreListResponse{Keys: keys}, nil
}

// --- Policy ---

type policyServer struct {
	agentv1.UnimplementedPolicyServiceServer
	s      *Services
	module string
}

func (v *policyServer) Get(
	ctx context.Context,
	_ *agentv1.PolicyGetRequest,
) (*agentv1.PolicyDocument, error) {
	rev, data, err := v.s.Policy.Get(ctx, v.module)
	if err != nil {
		return nil, grpcErr(err)
	}
	return &agentv1.PolicyDocument{Revision: rev, Data: data}, nil
}

func (v *policyServer) Watch(
	_ *agentv1.PolicyWatchRequest,
	stream agentv1.PolicyService_WatchServer,
) error {
	ctx := stream.Context()
	changes := v.s.Policy.Watch(ctx, v.module)
	var lastData []byte
	first := true
	for {
		rev, data, err := v.s.Policy.Get(ctx, v.module)
		if err != nil {
			return grpcErr(err)
		}
		// Send on content change, not on revision increase — a revision
		// reset (server restored from backup) still delivers the new
		// document rather than being silently ignored.
		if first || !bytes.Equal(data, lastData) {
			if err := stream.Send(&agentv1.PolicyDocument{Revision: rev, Data: data}); err != nil {
				return fmt.Errorf("policy watch: %w", err)
			}
			lastData = data
			first = false
		}
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-changes:
			if !ok {
				return nil
			}
		}
	}
}

// --- Events ---

type eventsServer struct {
	agentv1.UnimplementedEventBusServiceServer
	s      *Services
	module string
	allow  []string // declared subscribe allow-list (manifest.Subscribes)
}

func (v *eventsServer) Publish(
	ctx context.Context,
	req *agentv1.PublishRequest,
) (*agentv1.PublishResponse, error) {
	v.s.Bus.Publish(v.module, req.GetTopic(), req.GetData())
	return &agentv1.PublishResponse{}, nil
}

func (v *eventsServer) Subscribe(
	req *agentv1.SubscribeRequest,
	stream agentv1.EventBusService_SubscribeServer,
) error {
	// Authorize every requested topic against the module's declared
	// allow-list. Without this, a module could subscribe to "*" and
	// firehose every other module's events, undoing store isolation.
	for _, topic := range req.GetTopics() {
		if !topicAllowed(topic, v.allow) {
			return status.Errorf(
				codes.PermissionDenied,
				"module %q not authorized to subscribe to %q (declare it in the manifest's subscribes list)",
				v.module,
				topic,
			)
		}
	}
	sub := v.s.Bus.Subscribe(req.GetTopics()...)
	defer sub.Close()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-sub.C():
			if err := stream.Send(&agentv1.Event{
				Topic:         ev.Topic,
				Data:          ev.Data,
				PublishedAtMs: ev.PublishedAt.UnixMilli(),
				Sequence:      ev.Sequence,
			}); err != nil {
				return fmt.Errorf("event subscribe: %w", err)
			}
		}
	}
}

// --- Identity ---

type identityServer struct {
	agentv1.UnimplementedIdentityServiceServer
	s      *Services
	module string
}

func (v *identityServer) WhoAmI(
	ctx context.Context,
	_ *agentv1.WhoAmIRequest,
) (*agentv1.DeviceIdentity, error) {
	// An identity core could not load is refused rather than answered with
	// an empty one: a module told "ephemeral, no id" might act on that.
	if u, ok := v.s.Identity.(interface{ Unavailable() error }); ok {
		if err := u.Unavailable(); err != nil {
			//nolint:wrapcheck // a gRPC status is the handler's contract
			return nil, status.Error(codes.Unavailable, err.Error())
		}
	}
	id, eph, tenant := v.s.Identity.WhoAmI(ctx)
	return &agentv1.DeviceIdentity{DeviceId: id, Ephemeral: eph, Tenant: tenant}, nil
}

func (v *identityServer) Credential(
	ctx context.Context,
	req *agentv1.CredentialRequest,
) (*agentv1.CredentialResponse, error) {
	token, exp, granted, err := v.s.Identity.Credential(ctx, v.module, req.GetScopes())
	if err != nil {
		// Fail closed and say so plainly, so a module never mistakes an
		// unimplemented mint for a usable credential.
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return nil, status.Error(codes.Unimplemented, err.Error())
	}
	return &agentv1.CredentialResponse{Token: token, ExpiresAt: exp, GrantedScopes: granted}, nil
}

// --- Transport ---

type transportServer struct {
	agentv1.UnimplementedTransportServiceServer
	s      *Services
	module string
}

func (v *transportServer) Send(
	ctx context.Context,
	req *agentv1.TransportSendRequest,
) (*agentv1.TransportSendResponse, error) {
	m := req.GetMessage()
	delivered, err := v.s.Transport.Send(
		ctx,
		v.module,
		m.GetPeer(),
		m.GetKind(),
		m.GetData(),
		req.GetQueueOffline(),
	)
	if err != nil {
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &agentv1.TransportSendResponse{Delivered: delivered}, nil
}

func (v *transportServer) Receive(
	_ *agentv1.TransportReceiveRequest,
	stream agentv1.TransportService_ReceiveServer,
) error {
	ctx := stream.Context()
	inbound := v.s.Transport.Receive(ctx, v.module)
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-inbound:
			if !ok {
				return nil
			}
			if err := stream.Send(msg); err != nil {
				return fmt.Errorf("transport receive: %w", err)
			}
		}
	}
}

// --- Log ---

type logServer struct {
	agentv1.UnimplementedLogServiceServer
	s      *Services
	module string
}

// Write receives a module's structured log records and re-emits them
// through core's logger, attributed to the module. This is the wired
// LogService: module logs land in core's pipeline with level/time/attrs
// intact, rather than being scraped from stderr as opaque lines.
func (v *logServer) Write(
	stream grpc.ClientStreamingServer[agentv1.LogRecord, agentv1.LogWriteResponse],
) error {
	for {
		rec, err := stream.Recv()
		if err != nil {
			// io.EOF is the normal end of a client stream.
			if err.Error() == "EOF" {
				if err := stream.SendAndClose(&agentv1.LogWriteResponse{}); err != nil {
					return fmt.Errorf("log write: %w", err)
				}
				return nil
			}
			return fmt.Errorf("log write: %w", err)
		}
		attrs := []any{"module", v.module}
		for k, val := range rec.GetAttrs() {
			attrs = append(attrs, k, val)
		}
		v.s.Log.LogAttrs(stream.Context(), slog.Level(rec.GetLevel()), rec.GetMessage(),
			slogArgs(attrs)...)
	}
}

// slogArgs converts the alternating key/value slice into slog.Attr values.
func slogArgs(kv []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		out = append(out, slog.Any(key, kv[i+1]))
	}
	return out
}

// --- Watchdog ---

type watchdogServer struct {
	agentv1.UnimplementedWatchdogServiceServer
	s      *Services
	module string
}

// Notify receives the module's watchdog pings and reports each to the
// supervisor via the Watchdog seam, so a module that stops pinging within
// the deadline gets restarted. The stream lives for the module's runtime;
// its close (module Stop) is a normal end, not an error.
func (v *watchdogServer) Notify(
	stream grpc.ClientStreamingServer[agentv1.WatchdogPing, agentv1.WatchdogSummary],
) error {
	var received uint64
	for {
		ping, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if err := stream.SendAndClose(
					&agentv1.WatchdogSummary{Received: received},
				); err != nil {
					return fmt.Errorf("watchdog notify: %w", err)
				}
				return nil
			}
			return fmt.Errorf("watchdog notify: %w", err)
		}
		received = ping.GetSequence()
		if v.s.Watchdog != nil {
			v.s.Watchdog(v.module)
		}
	}
}
