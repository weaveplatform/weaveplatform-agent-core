package platform

import "testing"

func TestFillReadsMacOSVersion(t *testing.T) {
	var info Info
	fill(&info)
	if info.Version == "" || info.Build == "" {
		t.Fatalf("kern.osproductversion/kern.osversion not read: %+v", info)
	}
	if p := Paths(); p.StateDir != "/Library/Application Support/Weave" {
		t.Errorf("StateDir = %q", p.StateDir)
	}
}
