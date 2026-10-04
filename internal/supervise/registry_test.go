package supervise

import (
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
)

// The supervisor records into the registry it is given, so core's other
// readers see what it sees, and takes a module out only once it has stopped.
func TestSupervisorFeedsTheRegistry(t *testing.T) {
	reg := registry.New()
	sup, _, _ := capturingSupervisor(t)
	sup.Registry = reg
	changes := reg.Watch(t.Context())

	mf := testManifest("no.such.capability")
	mf.Address = "weave.test"
	if err := sup.Add(Spec{Manifest: mf, BinPath: "unused"}); err != nil {
		t.Fatal(err)
	}
	if sup.Modules() != reg {
		t.Fatal("Modules() is not the registry the supervisor was given")
	}
	m, ok := reg.ByAddress("weave.test")
	if !ok {
		t.Fatal("the module is not in the registry under its channel address")
	}
	if m.ID != mf.ID || m.State != StateRequirementsUnmet ||
		len(m.Capabilities) != 1 || m.Privilege != mf.Privilege || m.Session != mf.Session ||
		m.Detail == "" || m.Since.IsZero() {
		t.Fatalf("entry = %+v", m)
	}
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("registering a module did not notify")
	}

	sup.StopModule(mf.ID)
	if _, ok := reg.Get(mf.ID); ok {
		t.Fatal("a stopped module stayed in the registry")
	}
}

func TestModulesWithoutARegistry(t *testing.T) {
	sup := &Supervisor{}
	if sup.Modules() == nil || sup.Modules() != sup.Modules() {
		t.Fatal("Modules() did not settle on one private registry")
	}
	if len(sup.Statuses()) != 0 {
		t.Fatal("a fresh supervisor reports modules")
	}
}
