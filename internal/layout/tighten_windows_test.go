package layout

import "testing"

// Windows access is ACL-governed; tightenDir must not fail an Ensure on a
// directory it has nothing to do to.
func TestTightenDirIsANoOpOnWindows(t *testing.T) {
	if err := tightenDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
