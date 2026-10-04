package hostserv

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
)

func registryClient(t *testing.T, reg RegistryBackend) agentv1.RegistryServiceClient {
	t.Helper()
	s := testServices()
	s.Registry = reg
	_, conn := serveServer(t, s.NewServer("caller", "caller", "tok", nil))
	return agentv1.NewRegistryServiceClient(conn)
}

func TestRegistryList(t *testing.T) {
	reg := registry.New()
	reg.Set(registry.Module{
		ID: "weave-linux-power", Version: "1.0.0", Address: "weave.power",
		State: registry.StateRunning, PID: 99, Privilege: "system",
		Health: &agentv1.Health{Status: agentv1.Health_STATUS_HEALTHY},
	})
	reg.Set(registry.Module{ID: "caller", Address: "caller", State: registry.StateRunning})
	cli := registryClient(t, reg)

	if _, err := cli.List(
		context.Background(),
		&agentv1.RegistryListRequest{},
	); status.Code(
		err,
	) != codes.Unauthenticated {
		t.Fatalf("List without the token: %v", err)
	}
	snap, err := cli.List(withToken("tok"), &agentv1.RegistryListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if snap.GetRevision() != 2 || len(snap.GetModules()) != 2 {
		t.Fatalf("snapshot = %v", snap)
	}
	m := snap.GetModules()[1]
	if m.GetId() != "weave-linux-power" || m.GetVersion() != "1.0.0" ||
		m.GetAddress() != "weave.power" || m.GetState() != "running" ||
		m.GetHealth().GetStatus() != agentv1.Health_STATUS_HEALTHY {
		t.Fatalf("module = %v", m)
	}
}

func TestRegistryWatch(t *testing.T) {
	reg := registry.New()
	reg.Set(registry.Module{ID: "a", Address: "a", State: registry.StateStarting})
	cli := registryClient(t, reg)

	ctx, cancel := context.WithCancel(withToken("tok"))
	defer cancel()
	stream, err := cli.Watch(ctx, &agentv1.RegistryWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.GetModules()) != 1 || first.GetModules()[0].GetState() != "starting" {
		t.Fatalf("first snapshot = %v", first)
	}
	reg.Set(registry.Module{ID: "a", Address: "a", State: registry.StateRunning})
	next, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if next.GetRevision() <= first.GetRevision() || next.GetModules()[0].GetState() != "running" {
		t.Fatalf("after a change = %v", next)
	}
}

func TestRegistryUnavailable(t *testing.T) {
	cli := registryClient(t, nil)
	if _, err := cli.List(
		withToken("tok"),
		&agentv1.RegistryListRequest{},
	); status.Code(
		err,
	) != codes.Unavailable {
		t.Fatalf("List: %v", err)
	}
	stream, err := cli.Watch(withToken("tok"), &agentv1.RegistryWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("Watch: %v", err)
	}
}

func TestRegistryWatchEnds(t *testing.T) {
	reg := registry.New()
	v := &registryServer{s: &Services{Registry: reg}}

	// A send failure ends the stream with the error.
	st := &sendStream[agentv1.RegistrySnapshot]{ctx: context.Background(), sendErr: errBoom}
	if err := v.Watch(&agentv1.RegistryWatchRequest{}, st); err == nil {
		t.Fatal("a failed send did not end Watch")
	}

	// The caller going away ends it cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	st = &sendStream[agentv1.RegistrySnapshot]{ctx: ctx, onSend: func(int) { cancel() }}
	done := make(chan error, 1)
	go func() { done <- v.Watch(&agentv1.RegistryWatchRequest{}, st) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not end with its context")
	}
}
