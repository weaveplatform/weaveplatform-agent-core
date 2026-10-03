package buildinfo

import "testing"

func TestDefaults(t *testing.T) {
	if Version() != "devel" || Commit() != "" || BuildDate() != "" {
		t.Fatalf("unexpected defaults: %q %q %q", Version(), Commit(), BuildDate())
	}
}
