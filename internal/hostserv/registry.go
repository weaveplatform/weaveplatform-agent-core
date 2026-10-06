package hostserv

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
)

// registryServer is read-only and open to every module, behind the same
// token gate as the other host services and nothing more. What it shows —
// which modules are installed, where they answer and whether they are up — is
// what any module could already learn by sending to an address and seeing
// what comes back, so a per-module allow-list would protect nothing; process
// ids and placement, which would say more, are left out of the message.
type registryServer struct {
	agentv1.UnimplementedRegistryServiceServer
	s *Services
}

func (v *registryServer) List(
	_ context.Context,
	_ *agentv1.RegistryListRequest,
) (*agentv1.RegistrySnapshot, error) {
	if v.s.Registry == nil {
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return nil, status.Error(codes.Unavailable, "module registry not available")
	}
	return v.snapshot(), nil
}

func (v *registryServer) Watch(
	_ *agentv1.RegistryWatchRequest,
	stream agentv1.RegistryService_WatchServer,
) error {
	if v.s.Registry == nil {
		//nolint:wrapcheck // a gRPC status is the handler's contract
		return status.Error(codes.Unavailable, "module registry not available")
	}
	ctx := stream.Context()
	// Subscribed before the first snapshot, so a change between the two is
	// signalled rather than lost.
	changes := v.s.Registry.Watch(ctx)
	for {
		if err := stream.Send(v.snapshot()); err != nil {
			return fmt.Errorf("registry watch: %w", err)
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

func (v *registryServer) snapshot() *agentv1.RegistrySnapshot {
	rev, mods := v.s.Registry.List()
	out := &agentv1.RegistrySnapshot{
		Revision: rev,
		Modules:  make([]*agentv1.RegisteredModule, 0, len(mods)),
	}
	if c := v.s.Registry.Core(); c.Degraded != "" {
		out.Core = &agentv1.CoreCondition{
			Degraded: true, Reason: c.Degraded, Unavailable: c.Unavailable,
		}
	}
	for _, m := range mods {
		out.Modules = append(out.Modules, &agentv1.RegisteredModule{
			Id:      m.ID,
			Version: m.Version,
			Address: m.Address,
			State:   string(m.State),
			Health:  m.Health,
		})
	}
	return out
}
