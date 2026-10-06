package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
)

// registryGuest is a guest end with a registry wired the way core wires it,
// and the host's key, so a test can authenticate for real.
type registryGuest struct {
	mux  *Mux
	reg  *registry.Registry
	priv ed25519.PrivateKey
	r    *bufio.Reader
	w    *bufio.Writer
}

func newRegistryGuest(t *testing.T) *registryGuest {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guestConn, hostConn := net.Pipe()
	log := slog.New(slog.DiscardHandler)
	reg := registry.New()
	mux := &Mux{Log: log, Registry: reg}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		hostConn.Close()
	})
	p := newPeer(guestConn, log, mux.deliver, newChannelAuth(log, writeKeyFile(t, pub)))
	p.modules = reg
	mux.Hypervisor = p
	p.start(ctx)
	return &registryGuest{
		mux: mux, reg: reg, priv: priv,
		r: bufio.NewReader(hostConn), w: bufio.NewWriter(hostConn),
	}
}

func sendEnv(t *testing.T, w *bufio.Writer, env hvchannel.Envelope) {
	t.Helper()
	if err := hvchannel.WriteEnvelope(w, env); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (g *registryGuest) authenticate(t *testing.T) {
	t.Helper()
	send(t, g.w, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(readEnvelope(t, g.r).Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, err := hvchannel.Sign(g.priv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	send(t, g.w, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)
	var result hvchannel.AuthResult
	if err := json.Unmarshal(readEnvelope(t, g.r).Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("authentication refused: %s", result.Reason)
	}
}

// expectFailure reads one frame and checks it is a delivery.failed for the
// given call.
func expectFailure(t *testing.T, r *bufio.Reader, id string) hvchannel.DeliveryFailed {
	t.Helper()
	env := readEnvelope(t, r)
	if env.Module != hvchannel.ControlModule || env.Kind != hvchannel.KindDeliveryFailed {
		t.Fatalf("got %s/%s, want %s/%s", env.Module, env.Kind,
			hvchannel.ControlModule, hvchannel.KindDeliveryFailed)
	}
	if env.ID != id {
		t.Fatalf("correlation id = %q, want %q", env.ID, id)
	}
	var f hvchannel.DeliveryFailed
	if err := json.Unmarshal(env.Data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDeliveryFailedNotInstalled(t *testing.T) {
	g := newRegistryGuest(t)
	g.authenticate(t)
	sendEnv(t, g.w, hvchannel.Envelope{
		Module: "weave.power", Kind: "weave.power.shutdown", Data: []byte(`{"id":"p1"}`), ID: "c1",
	})
	f := expectFailure(t, g.r, "c1")
	if f.Reason != hvchannel.ReasonNotInstalled || f.Module != "weave.power" ||
		f.Kind != "weave.power.shutdown" || f.State != "" {
		t.Fatalf("failure = %+v", f)
	}
}

func TestDeliveryFailedNotRunningCarriesTheState(t *testing.T) {
	g := newRegistryGuest(t)
	// Registered before authenticating, so no modules.changed is in flight.
	g.reg.Set(registry.Module{
		ID: "weave-linux-clipboard", Address: "weave.clipboard",
		State: registry.StateWaitingForSession, Detail: "no console user session",
	})
	g.authenticate(t)
	sendEnv(t, g.w, hvchannel.Envelope{
		Module: "weave.clipboard", Kind: "weave.clipboard.get", ID: "c2",
	})
	f := expectFailure(t, g.r, "c2")
	if f.Reason != hvchannel.ReasonNotRunning ||
		f.State != string(registry.StateWaitingForSession) ||
		f.Detail != "no console user session" {
		t.Fatalf("failure = %+v", f)
	}
}

func TestDeliveryFailedBusy(t *testing.T) {
	setInboundWait(t, 50*time.Millisecond)
	g := newRegistryGuest(t)
	g.reg.Set(
		registry.Module{
			ID:      "weave-linux-exec",
			Address: "weave.exec",
			State:   registry.StateRunning,
		},
	)
	g.authenticate(t)
	// A receiver that never reads, filled to its bound.
	g.mux.Receive(t.Context(), "weave.exec")
	for range inboundBuffer {
		if f := g.mux.deliver("weave.exec", "weave.exec.stdin", nil); f != nil {
			t.Fatalf("delivery into a queue with room failed: %+v", f)
		}
	}
	sendEnv(t, g.w, hvchannel.Envelope{Module: "weave.exec", Kind: "weave.exec.run", ID: "c3"})
	if f := expectFailure(t, g.r, "c3"); f.Reason != hvchannel.ReasonBusy || f.State != "" {
		t.Fatalf("failure = %+v", f)
	}
}

// A frame sent without an id still gets its answer; there is just nothing to
// echo, and the field is absent rather than empty.
func TestDeliveryFailedWithoutCorrelation(t *testing.T) {
	g := newRegistryGuest(t)
	g.authenticate(t)
	send(t, g.w, "weave.power", "weave.power.shutdown", nil)
	env := readEnvelope(t, g.r)
	if env.Kind != hvchannel.KindDeliveryFailed || env.ID != "" {
		t.Fatalf("got %+v", env)
	}
}

// Before authentication the channel says nothing about which modules exist:
// a hello for a module that is not there goes unanswered, exactly as before.
func TestNoDeliveryFailedBeforeAuthentication(t *testing.T) {
	g := newRegistryGuest(t)
	sendEnv(t, g.w, hvchannel.Envelope{
		Module: "weave.presence", Kind: hvchannel.PreAuthKind, ID: "h1",
	})
	send(t, g.w, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	if env := readEnvelope(t, g.r); env.Kind != hvchannel.KindAuthChallenge {
		t.Fatalf("first frame back was %q; a pre-auth hello was answered", env.Kind)
	}
	// And a gated op is still refused, with its id echoed on the refusal.
	sendEnv(
		t,
		g.w,
		hvchannel.Envelope{Module: "weave.power", Kind: "weave.power.shutdown", ID: "p9"},
	)
	if env := readEnvelope(t, g.r); env.Kind != hvchannel.KindAuthResult || env.ID != "p9" {
		t.Fatalf("refusal = %+v", env)
	}
}

func TestModulesListRefusedBeforeAuthentication(t *testing.T) {
	g := newRegistryGuest(t)
	g.reg.Set(registry.Module{ID: "secret", Address: "secret", State: registry.StateRunning})
	sendEnv(
		t,
		g.w,
		hvchannel.Envelope{
			Module: hvchannel.ControlModule,
			Kind:   hvchannel.KindModulesList,
			ID:     "l0",
		},
	)
	env := readEnvelope(t, g.r)
	if env.Kind != hvchannel.KindAuthResult || env.ID != "l0" {
		t.Fatalf("got %+v", env)
	}
	var res hvchannel.AuthResult
	if err := json.Unmarshal(env.Data, &res); err != nil || res.OK {
		t.Fatalf("refusal = %+v (%v)", res, err)
	}
}

func decodeSnapshot(t *testing.T, env hvchannel.Envelope) hvchannel.ModulesSnapshot {
	t.Helper()
	var snap hvchannel.ModulesSnapshot
	if err := json.Unmarshal(env.Data, &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestModulesListAndChanged(t *testing.T) {
	g := newRegistryGuest(t)
	since := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	g.reg.Set(registry.Module{
		ID: "weave-linux-power", Version: "1.2.3", Protocol: 1, Address: "weave.power",
		Capabilities: []string{"hypervisor.channel"}, Privilege: "system", Session: "system",
		State: registry.StateRunning, Restarts: 2, Since: since,
		Health: &agentv1.Health{Status: agentv1.Health_STATUS_DEGRADED, Reason: "slow"},
	})
	g.authenticate(t)

	sendEnv(
		t,
		g.w,
		hvchannel.Envelope{
			Module: hvchannel.ControlModule,
			Kind:   hvchannel.KindModulesList,
			ID:     "l1",
		},
	)
	env := readEnvelope(t, g.r)
	if env.Module != hvchannel.ControlModule || env.Kind != hvchannel.KindModulesListResult ||
		env.ID != "l1" {
		t.Fatalf("got %s/%s id %q", env.Module, env.Kind, env.ID)
	}
	// The exact bytes, because the SDK decodes them from the documented shape.
	want := `{"revision":1,"modules":[{"id":"weave-linux-power","version":"1.2.3","protocol":1,` +
		`"address":"weave.power","capabilities":["hypervisor.channel"],"privilege":"system",` +
		`"session":"system","state":"running","health":{"status":"degraded","reason":"slow"},` +
		`"restarts":2,"since":"2026-10-04T12:00:00Z"}]}`
	if string(env.Data) != want {
		t.Fatalf("modules.list.result\n got %s\nwant %s", env.Data, want)
	}

	g.reg.Set(
		registry.Module{
			ID:      "weave-linux-exec",
			Address: "weave.exec",
			State:   registry.StateStarting,
		},
	)
	changed := readEnvelope(t, g.r)
	if changed.Kind != hvchannel.KindModulesChanged || changed.ID != "" {
		t.Fatalf("got %+v", changed)
	}
	snap := decodeSnapshot(t, changed)
	if snap.Revision != 2 || len(snap.Modules) != 2 || snap.Modules[0].ID != "weave-linux-exec" ||
		snap.Modules[0].Health.Status != hvchannel.HealthUnknown {
		t.Fatalf("changed = %+v", snap)
	}
	if !strings.Contains(string(changed.Data), `"capabilities":[]`) {
		t.Errorf("a module without capabilities must carry an empty array: %s", changed.Data)
	}

	g.reg.Remove("weave-linux-exec")
	if snap := decodeSnapshot(
		t,
		readEnvelope(t, g.r),
	); snap.Revision != 3 ||
		len(snap.Modules) != 1 {
		t.Fatalf("after remove = %+v", snap)
	}
}

func TestSnapshotOfNoRegistry(t *testing.T) {
	snap := snapshot(nil)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"revision":0,"modules":[]}` {
		t.Fatalf("got %s", raw)
	}
}

func TestHealthStatus(t *testing.T) {
	for h, want := range map[*agentv1.Health]string{
		nil: hvchannel.HealthUnknown,
		{Status: agentv1.Health_STATUS_UNSPECIFIED}: hvchannel.HealthUnknown,
		{Status: agentv1.Health_STATUS_HEALTHY}:     hvchannel.HealthHealthy,
		{Status: agentv1.Health_STATUS_DEGRADED}:    hvchannel.HealthDegraded,
		{Status: agentv1.Health_STATUS_UNHEALTHY}:   hvchannel.HealthUnhealthy,
	} {
		if got := healthStatus(h); got != want {
			t.Errorf("healthStatus(%v) = %q, want %q", h, got, want)
		}
	}
}

func TestUndeliverableWithoutRegistry(t *testing.T) {
	m := &Mux{Log: slog.New(slog.DiscardHandler)}
	if f := m.deliver("anything", "k", nil); f == nil || f.Reason != hvchannel.ReasonNotInstalled {
		t.Fatalf("got %+v", f)
	}
}

// A degraded core says so in the snapshot a host reads; a whole one carries no
// core field at all, so the shape hosts already decode is unchanged.
func TestSnapshotCarriesCoreCondition(t *testing.T) {
	reg := registry.New()
	raw, err := json.Marshal(snapshot(reg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"core"`) {
		t.Fatalf("a whole core reported a condition: %s", raw)
	}
	reg.SetCore(registry.Core{Degraded: "store sealed elsewhere"})
	raw, err = json.Marshal(snapshot(reg))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw),
		`"core":{"degraded":true,"reason":"store sealed elsewhere","unavailable":[]}`) {
		t.Fatalf("got %s", raw)
	}
}
