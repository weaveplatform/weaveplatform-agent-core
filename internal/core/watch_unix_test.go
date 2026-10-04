//go:build linux || darwin

package core

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// counter counts notifications from the watch.
type counter struct{ n atomic.Int32 }

func (c *counter) notify() { c.n.Add(1) }

// settle waits for the watch to go quiet and returns the count.
func (c *counter) settle() int32 {
	last := c.n.Load()
	for {
		time.Sleep(150 * time.Millisecond)
		now := c.n.Load()
		if now == last {
			return now
		}
		last = now
	}
}

func (c *counter) waitAbove(t *testing.T, n int32, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for c.n.Load() <= n {
		if time.Now().After(deadline) {
			t.Fatalf("no notification for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startWatch(t *testing.T, dir string) *counter {
	t.Helper()
	c := &counter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchModules(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), dir, c.notify)
	}()
	t.Cleanup(func() { cancel(); <-done })
	// The watch notifies once when it is in place.
	c.waitAbove(t, 0, "the watch starting")
	return c
}

// The watch follows module directories as they come and go, and ignores
// dpkg's in-progress files until dpkg renames them into place.
func TestWatchModuleDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := startWatch(t, dir)

	n := c.settle()
	writeFile(t, filepath.Join(dir, "existing", "config.json"), "{}")
	c.waitAbove(t, n, "a write in a module directory present at start")

	n = c.settle()
	if err := os.Mkdir(filepath.Join(dir, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a new module directory")

	// dpkg unpacking into the new directory: the .dpkg-new file is silent,
	// its rename into place is not.
	n = c.settle()
	staged := filepath.Join(dir, "new", "new.dpkg-new")
	writeFile(t, staged, "half a binary")
	if got := c.settle(); got != n {
		t.Fatalf("a .dpkg-new file notified (%d → %d)", n, got)
	}
	if err := os.Rename(staged, filepath.Join(dir, "new", "new")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "the rename into place")

	// A removed module directory, then one recreated under the same name,
	// which must be watched again.
	n = c.settle()
	if err := os.RemoveAll(filepath.Join(dir, "new")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a removed module directory")
	n = c.settle()
	if err := os.Mkdir(filepath.Join(dir, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a recreated module directory")
	n = c.settle()
	writeFile(t, filepath.Join(dir, "new", "module.manifest.json"), "{}")
	c.waitAbove(t, n, "a write in the recreated directory")

	// Moved away: dropped from the watch.
	n = c.settle()
	if err := os.Rename(filepath.Join(dir, "new"), filepath.Join(t.TempDir(), "away")); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "a module directory moved away")
}

// The modules directory itself removed and recreated: the watch says so and
// picks the new directory up.
func TestWatchModulesDirReplaced(t *testing.T) {
	old := watchRetry
	watchRetry = 20 * time.Millisecond
	t.Cleanup(func() { watchRetry = old })
	dir := filepath.Join(t.TempDir(), "modules")
	// Absent at start: the watch keeps trying.
	c := &counter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchModules(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), dir, c.notify)
	}()
	t.Cleanup(func() { cancel(); <-done })

	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	n := c.settle()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	c.waitAbove(t, n, "the modules directory removed")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	n = c.settle()
	writeFile(t, filepath.Join(dir, "m", "x"), "")
	c.waitAbove(t, n, "a module in the recreated modules directory")
}

// End to end: a module package unpacked into a running core's modules
// directory, dpkg style, starts without anyone asking.
func TestWatchDrivesReload(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.rec.debounce = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() { h.rec.run(ctx); done <- struct{}{} }()
	go func() { watchModules(ctx, h.rec.log, h.dir, h.rec.trigger); done <- struct{}{} }()
	t.Cleanup(func() { cancel(); <-done; <-done })
	time.Sleep(100 * time.Millisecond)

	// Unpacked under .dpkg-new names first: nothing to see yet.
	src := filepath.Join(t.TempDir(), "pkg")
	h2 := &harness{dir: src}
	h2.install(t, fixtureID, "1.0.0", "", "platform.osinfo")
	mdir := filepath.Join(h.dir, fixtureID)
	if err := os.Mkdir(mdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{exe(fixtureID), "module.manifest.json"} {
		copyFile(t, filepath.Join(src, fixtureID, f), filepath.Join(mdir, f+".dpkg-new"))
	}
	time.Sleep(300 * time.Millisecond)
	if _, ok := h.status(fixtureID); ok {
		t.Fatal("registered from .dpkg-new files")
	}
	for _, f := range []string{exe(fixtureID), "module.manifest.json"} {
		if err := os.Rename(
			filepath.Join(mdir, f+".dpkg-new"),
			filepath.Join(mdir, f),
		); err != nil {
			t.Fatal(err)
		}
	}
	h.waitRunning(t, fixtureID, "1.0.0")

	if err := os.RemoveAll(mdir); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := h.status(fixtureID); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("removed module still registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
