package core

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	systemio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"
)

func TestIgnoredNameWindows(t *testing.T) {
	for name, want := range map[string]bool{
		"weave-windows-exec.exe.new": true, "module.manifest.json.NEW": true,
		"~DF1234.tmp": true, "x.TMP": true, ".install-42": true, ".tmp-1": true, "m.dpkg-new": true,
		"weave-windows-exec.exe": false, "module.manifest.json": false, "config.json": false,
		"current": false, "versions": false, "newer": false,
	} {
		if ignoredName(name) != want {
			t.Errorf("ignoredName(%q) = %v", name, !want)
		}
	}
	for rel, want := range map[string]bool{
		`m\.tmp-1\weave.exe`: true, `m\x.exe.new`: true, `m\versions\1.0.0\m.exe`: false,
	} {
		if ignoredPath(rel) != want {
			t.Errorf("ignoredPath(%q) = %v", rel, !want)
		}
	}
}

// The way agent-modules' module zip installs on Windows: each file staged as
// <name>.new beside its destination and File.Replace'd over it; MSI-style
// ~*.tmp files beside it. Only the landing counts.
func TestWatchWindowsInstallerNames(t *testing.T) {
	dir := t.TempDir()
	mdir := filepath.Join(dir, "weave-windows-exec")
	if err := os.Mkdir(mdir, 0o755); err != nil {
		t.Fatal(err)
	}
	c := startWatch(t, dir)

	n := c.settle()
	staged := filepath.Join(mdir, "weave-windows-exec.exe.new")
	writeFile(t, staged, "a binary")
	writeFile(t, filepath.Join(mdir, "~DF12.tmp"), "msi")
	writeFile(t, filepath.Join(dir, ".install-1"), "weaveboot")
	if got := c.settle(); got != n {
		t.Fatalf("staged files notified (%d → %d)", n, got)
	}
	if err := os.Rename(staged, filepath.Join(mdir, "weave-windows-exec.exe")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "the rename into place")

	// A write in place, deeper than a module directory.
	n = c.settle()
	writeFile(t, filepath.Join(mdir, "versions", "1.0.0", "weave-windows-exec.exe"), "v1")
	c.waitAbove(t, n, "a file in a version directory")
}

// More changes than the buffer holds still notify: the lost events are
// reported as an overflow, which counts as a change.
func TestWatchWindowsOverflow(t *testing.T) {
	old := watchBuffer
	watchBuffer = 8
	t.Cleanup(func() { watchBuffer = old })
	dir := t.TempDir()
	c := startWatch(t, dir)
	n := c.settle()
	writeFile(t, filepath.Join(dir, "m", "module.manifest.json"), "{}")
	c.waitAbove(t, n, "an overflowed buffer")
}

// record encodes one FILE_NOTIFY_INFORMATION entry; next is its
// NextEntryOffset.
func record(action filesystem.FILE_ACTION, name string, next uint32) []byte {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 12+2*len(u))
	binary.LittleEndian.PutUint32(b[0:], next)
	binary.LittleEndian.PutUint32(b[4:], uint32(action))
	binary.LittleEndian.PutUint32(b[8:], uint32(2*len(u)))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[12+2*i:], v)
	}
	return b
}

func TestChangedNames(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	one := func(action filesystem.FILE_ACTION, name string) bool {
		return changedNames(root, record(action, name, 0))
	}
	switch {
	case one(filesystem.FILE_ACTION_ADDED, `m\x.exe.new`):
		t.Fatal("a staged file counted")
	case one(filesystem.FILE_ACTION_MODIFIED, `m`):
		t.Fatal("a module directory's own timestamp counted")
	case !one(filesystem.FILE_ACTION_MODIFIED, `m\config.json`):
		t.Fatal("a file written in place did not count")
	case !one(filesystem.FILE_ACTION_REMOVED, `gone`):
		t.Fatal("a removal did not count")
	case !one(filesystem.FILE_ACTION_ADDED, `m`):
		t.Fatal("a new module directory did not count")
	}
	// Two entries, the second the one that counts.
	first := record(filesystem.FILE_ACTION_ADDED, `m\a.tmp`, 0)
	first = append(first, make([]byte, (4-len(first)%4)%4)...)
	binary.LittleEndian.PutUint32(first[0:], uint32(len(first)))
	if !changedNames(
		root,
		append(first, record(filesystem.FILE_ACTION_RENAMED_NEW_NAME, `m\a.exe`, 0)...),
	) {
		t.Fatal("the second entry was not read")
	}
	// Truncated: a name running past the end is not read.
	if changedNames(root, record(filesystem.FILE_ACTION_ADDED, `m\a.exe`, 0)[:14]) {
		t.Fatal("a truncated entry counted")
	}
}

func TestWatchOnceWindowsFailures(t *testing.T) {
	if err := watchOnce(
		context.Background(),
		filepath.Join(t.TempDir(), "absent"),
		func() {},
	); err == nil {
		t.Fatal("watching a directory that is not there")
	}
	errBoom := errors.New("boom")

	oldE, oldR := createEvent, readChanges
	t.Cleanup(func() { createEvent, readChanges = oldE, oldR })
	createEvent = func() (foundation.HANDLE, error) { return 0, errBoom }
	if err := watchOnce(context.Background(), t.TempDir(), func() {}); !errors.Is(err, errBoom) {
		t.Fatalf("event failure: %v", err)
	}
	createEvent = oldE
	readChanges = func(foundation.HANDLE, []byte, bool, filesystem.FILE_NOTIFY_CHANGE, *uint32,
		*systemio.OVERLAPPED, systemio.LPOVERLAPPED_COMPLETION_ROUTINE,
	) error {
		return errBoom
	}
	if err := watchOnce(context.Background(), t.TempDir(), func() {}); !errors.Is(err, errBoom) {
		t.Fatalf("read failure: %v", err)
	}
	readChanges = oldR

	// Already cancelled: the first read is never issued.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := watchOnce(ctx, t.TempDir(), func() {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled watch: %v", err)
	}
}
