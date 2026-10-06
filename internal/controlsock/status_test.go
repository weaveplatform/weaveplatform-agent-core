package controlsock

import (
	"context"
	"testing"
	"time"

	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/registry"
)

// Status carries core's own condition from the registry while it is degraded,
// and nothing while it is whole.
func TestStatusReportsCoreCondition(t *testing.T) {
	reg := registry.New()
	srv := &Server{Identity: stubIdentity{}, StartedAt: time.Now(), Registry: reg}
	st, err := srv.Status(context.Background(), &controlv1.StatusRequest{})
	if err != nil || st.GetCore() != nil {
		t.Fatalf("Status = %v, %v", st, err)
	}
	reg.SetCore(registry.Core{Degraded: "store sealed elsewhere", Unavailable: []string{"store"}})
	st, err = srv.Status(context.Background(), &controlv1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if c := st.GetCore(); !c.GetDegraded() || c.GetReason() != "store sealed elsewhere" ||
		len(c.GetUnavailable()) != 1 {
		t.Fatalf("core = %v", c)
	}
}
