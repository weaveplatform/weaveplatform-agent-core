package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestNMinus1RetentionOnDisk installs three versions in sequence and asserts
// the on-disk version tree keeps exactly the current and previous versions —
// the oldest is pruned, so retention can't grow unbounded across upgrades.
func TestNMinus1RetentionOnDisk(t *testing.T) {
	mgr, sup, bin := newTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if _, err := mgr.InstallLocal(ctx, makeInstallDir(t, bin, v, 0)); err != nil {
			t.Fatalf("install %s: %v", v, err)
		}
		assertRunningVersion(t, sup, v)
	}

	versionsDir := filepath.Join(mgr.Layout.ModulesDir, "testmod", "versions")
	entries, err := readDirNames(versionsDir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.0", "1.2.0"} // previous + current; 1.0.0 pruned
	if len(entries) != len(want) {
		t.Fatalf("versions on disk = %v, want exactly %v (N-1 retention)", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Fatalf("versions on disk = %v, want %v", entries, want)
		}
	}
}

func readDirNames(dir string) ([]string, error) {
	fis, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fis))
	for _, fi := range fis {
		names = append(names, fi.Name())
	}
	sort.Strings(names)
	return names, nil
}
