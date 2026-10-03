package hostserv

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/eventbus"
	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/handshake"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/ipc"
)

func testServices() *Services {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &Services{
		Log:       log,
		Bus:       eventbus.New(),
		Store:     NewMemStore(),
		Policy:    NewMemPolicy(),
		Identity:  NewStubIdentity(),
		Transport: nil,
	}
}

// serve starts a per-module host server on a short-path unix socket and
// returns a dialed client conn plus a helper to attach a token.
func serve(t *testing.T, module, token string, subscribes []string) *grpc.ClientConn {
	t.Helper()
	_, conn := serveServer(t, testServices().NewServer(module, module, token, subscribes))
	return conn
}

// serveServer serves srv on a fresh per-test address and dials it.
func serveServer(t *testing.T, srv *grpc.Server) (string, *grpc.ClientConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// A socket path on unix, a pipe name on Windows — the same split
	// supervise.launch makes for a real module. ipc.Listen is a named-pipe
	// listener on Windows, and hands a filesystem path straight to CreateFile,
	// which fails with "Incorrect function": a test that skipped this was
	// testing an address production never uses.
	addr := filepath.Join(dir, "h.sock")
	if runtime.GOOS == "windows" {
		addr = `\\.\pipe\weave-hostserv-test-` + filepath.Base(dir)
	}
	lis, err := ipc.Listen(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)

	conn, err := ipc.GRPCClient(ipc.Network(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return addr, conn
}

func withToken(tok string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), handshake.TokenMetadataKey, tok)
}

func TestTokenGateRejects(t *testing.T) {
	conn := serve(t, "m", "the-right-token", nil)
	store := agentv1.NewStoreServiceClient(conn)

	cases := map[string]context.Context{
		"no token":    context.Background(),
		"wrong token": withToken("nope"),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err := store.Put(cctx, &agentv1.StorePutRequest{Key: "k", Value: []byte("v")})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("Put with %s: code = %v, want Unauthenticated", name, status.Code(err))
			}
		})
	}

	// The right token is accepted.
	cctx, cancel := context.WithTimeout(withToken("the-right-token"), 5*time.Second)
	defer cancel()
	if _, err := store.Put(
		cctx,
		&agentv1.StorePutRequest{Key: "k", Value: []byte("v")},
	); err != nil {
		t.Fatalf("Put with right token: %v", err)
	}
}

// TestTokenGateRejectsStream proves the gate also guards streaming RPCs,
// not just unary ones: the interceptor runs before the first Recv.
func TestTokenGateRejectsStream(t *testing.T) {
	conn := serve(t, "m", "the-right-token", nil)
	policy := agentv1.NewPolicyServiceClient(conn)

	cases := map[string]context.Context{
		"no token":    context.Background(),
		"wrong token": withToken("nope"),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			stream, err := policy.Watch(cctx, &agentv1.PolicyWatchRequest{})
			if err == nil {
				_, err = stream.Recv() // the gate fires here at the latest
			}
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("Watch with %s: code = %v, want Unauthenticated", name, status.Code(err))
			}
		})
	}
}

// TestTokenGateRejectsCrossModuleToken proves a token minted for one module
// does not open another module's server: each server validates its own
// token, so a stolen sibling token is just a wrong token.
func TestTokenGateRejectsCrossModuleToken(t *testing.T) {
	// Two independent per-module servers with distinct tokens.
	connA := serve(t, "a", "token-a", nil)
	_ = serve(t, "b", "token-b", nil)

	storeA := agentv1.NewStoreServiceClient(connA)
	// Present module b's token to module a's server.
	cctx, cancel := context.WithTimeout(withToken("token-b"), 5*time.Second)
	defer cancel()
	_, err := storeA.Put(cctx, &agentv1.StorePutRequest{Key: "k", Value: []byte("v")})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf(
			"module a accepted module b's token: code = %v, want Unauthenticated",
			status.Code(err),
		)
	}
}

func TestSubscribeAuthorization(t *testing.T) {
	// Module may subscribe to "other.*" but not "secret.*" or "*".
	conn := serve(t, "m", "tok", []string{"other.*", "self.exact"})
	events := agentv1.NewEventBusServiceClient(conn)

	sub := func(topics ...string) error {
		ctx, cancel := context.WithTimeout(withToken("tok"), 5*time.Second)
		defer cancel()
		stream, err := events.Subscribe(ctx, &agentv1.SubscribeRequest{Topics: topics})
		if err != nil {
			return err
		}
		_, err = stream.Recv() // triggers server-side authorization
		return err
	}

	if err := sub("*"); status.Code(err) != codes.PermissionDenied {
		t.Errorf(`subscribe "*": code = %v, want PermissionDenied`, status.Code(err))
	}
	if err := sub("secret.token"); status.Code(err) != codes.PermissionDenied {
		t.Errorf(`subscribe "secret.token": code = %v, want PermissionDenied`, status.Code(err))
	}
	if err := sub("other.foo", "secret.x"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("mixed allowed+denied must be denied: code = %v", status.Code(err))
	}
	// An allowed subscription: no PermissionDenied (it will block on Recv
	// until the deadline, which is DeadlineExceeded — acceptable).
	if err := sub("other.foo"); status.Code(err) == codes.PermissionDenied {
		t.Errorf(`subscribe "other.foo" denied but is in the allow-list`)
	}
}
