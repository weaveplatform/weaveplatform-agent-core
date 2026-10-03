package capability

import (
	"runtime"
	"slices"
	"testing"
)

func TestProbeAlwaysReportsOSInfo(t *testing.T) {
	set := Probe()
	info, ok := set["platform.osinfo"]
	if !ok {
		t.Fatal("platform.osinfo missing; it is unconditional")
	}
	if info["os"] != runtime.GOOS || info["arch"] != runtime.GOARCH {
		t.Fatalf("osinfo = %v, want %s/%s", info, runtime.GOOS, runtime.GOARCH)
	}
}

func TestHasReportsOnlyTheMissing(t *testing.T) {
	set := Set{"a": nil, "b": {}}
	if missing := set.Has("a", "b"); len(missing) != 0 {
		t.Fatalf("Has(present) = %v", missing)
	}
	if missing := set.Has("a", "x", "y"); !slices.Equal(missing, []string{"x", "y"}) {
		t.Fatalf("Has = %v, want [x y]", missing)
	}
}
