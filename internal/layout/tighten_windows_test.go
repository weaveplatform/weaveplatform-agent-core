package layout

import "testing"

// Windows access is ACL-governed; setDirMode must not fail an Ensure on a
// directory it has nothing to do to.
func TestTightenDirIsANoOpOnWindows(t *testing.T) {
	if err := setDirMode(t.TempDir(), modePrivate); err != nil {
		t.Fatal(err)
	}
}
