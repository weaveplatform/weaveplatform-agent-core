package weaveboot

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer lets a test poll log output while Run writes it from another
// goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testLog(w *syncBuffer) *slog.Logger {
	if w == nil {
		w = &syncBuffer{}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestHigherSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0", "9.0.0", true},
		{"9.0.0", "10.0.0", false},
		{"1.2.3", "1.2.3", false},
		{"1.2.3.1", "1.2.3", true},
		{"1.2", "1.2.0", false},
		{"1.0.0-rc2", "1.0.0-rc1", true},
		{"1.0.x", "1.0.y", false},
		{"1.0.x", "1.0.x", false},
	}
	for _, c := range cases {
		if got := higherSemver(c.a, c.b); got != c.want {
			t.Errorf("higherSemver(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestBinaryNameMatchesPlatform(t *testing.T) {
	want := "weave-agent"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := binaryName(); got != want {
		t.Fatalf("binaryName() = %q, want %q", got, want)
	}
}

func TestCurrentBinary(t *testing.T) {
	t.Run("versioned", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "versions", "1.0.0", binaryName()), "bin")
		writeFile(t, filepath.Join(coreDir, "current"), " 1.0.0 \n")
		v, bin, err := currentBinary(coreDir)
		if err != nil || v != "1.0.0" ||
			bin != filepath.Join(coreDir, "versions", "1.0.0", binaryName()) {
			t.Fatalf("currentBinary = %q %q %v", v, bin, err)
		}
	})

	t.Run("current without binary", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "current"), "2.0.0\n")
		if _, _, err := currentBinary(
			coreDir,
		); err == nil ||
			!strings.Contains(err.Error(), "2.0.0 has no binary") {
			t.Fatalf("want missing-binary error, got %v", err)
		}
	})

	// A dev install has no versions tree: the binary sits beside weaveboot.
	t.Run("beside weaveboot", func(t *testing.T) {
		self := t.TempDir()
		stubExecutable(t, filepath.Join(self, "weaveboot"), nil)
		if _, _, err := currentBinary(
			t.TempDir(),
		); err == nil ||
			!strings.Contains(err.Error(), "no versioned core") {
			t.Fatalf("want no-core error, got %v", err)
		}
		writeFile(t, filepath.Join(self, binaryName()), "bin")
		v, bin, err := currentBinary(t.TempDir())
		if err != nil || v != "unversioned" || bin != filepath.Join(self, binaryName()) {
			t.Fatalf("currentBinary = %q %q %v", v, bin, err)
		}
	})

	t.Run("executable unknown", func(t *testing.T) {
		boom := errors.New("no executable")
		stubExecutable(t, "", boom)
		if _, _, err := currentBinary(t.TempDir()); !errors.Is(err, boom) {
			t.Fatalf("want %v, got %v", boom, err)
		}
	})
}

func stubExecutable(t *testing.T, path string, err error) {
	t.Helper()
	orig := executable
	executable = func() (string, error) { return path, err }
	t.Cleanup(func() { executable = orig })
}

func stage(t *testing.T, coreDir, version string) {
	t.Helper()
	writeFile(t, filepath.Join(coreDir, "staging", version, binaryName()), "core "+version)
}

func TestPromoteStagedPicksHighestAndChainsPrevious(t *testing.T) {
	coreDir := t.TempDir()
	writeFile(t, filepath.Join(coreDir, "current"), "1.0.0\n")
	stage(t, coreDir, "9.0.0")
	stage(t, coreDir, "10.0.0")
	// Neither a stray file nor a binary-less dir may be promoted.
	writeFile(t, filepath.Join(coreDir, "staging", "README"), "x")
	if err := os.MkdirAll(filepath.Join(coreDir, "staging", "99.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	var verified string
	promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir, VerifyCore: func(p string) error {
		verified = p
		return nil
	}})

	if verified != filepath.Join(coreDir, "staging", "10.0.0", binaryName()) {
		t.Fatalf("verified %q, want the 10.0.0 staged binary", verified)
	}
	if got := readMarker(coreDir, "current"); got != "10.0.0" {
		t.Fatalf("current = %q, want 10.0.0", got)
	}
	if got := readMarker(coreDir, "previous"); got != "1.0.0" {
		t.Fatalf("previous = %q, want 1.0.0", got)
	}
	if _, err := os.Stat(filepath.Join(coreDir, "versions", "10.0.0", binaryName())); err != nil {
		t.Fatalf("promoted binary missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(coreDir, "staging")); !os.IsNotExist(err) {
		t.Fatalf("staging dir should be cleared, stat err = %v", err)
	}
}

func TestPromoteStagedNothingUsable(t *testing.T) {
	coreDir := t.TempDir()
	promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir}) // no staging dir

	if err := os.MkdirAll(filepath.Join(coreDir, "staging", "2.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir, VerifyCore: func(string) error {
		t.Fatal("nothing promotable should reach the verifier")
		return nil
	}})
	if readMarker(coreDir, "current") != "" {
		t.Fatal("current written with nothing promotable")
	}
}

func TestPromoteStagedFailsClosed(t *testing.T) {
	t.Run("no verifier", func(t *testing.T) {
		coreDir := t.TempDir()
		stage(t, coreDir, "2.0.0")
		promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir})
		if readMarker(coreDir, "current") != "" {
			t.Fatal("promoted without a verifier")
		}
		// Left staged: a later boot with a verifier may still promote it.
		if _, err := os.Stat(filepath.Join(coreDir, "staging", "2.0.0")); err != nil {
			t.Fatalf("staged core should be kept: %v", err)
		}
	})

	t.Run("verification fails", func(t *testing.T) {
		coreDir := t.TempDir()
		stage(t, coreDir, "2.0.0")
		promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir, VerifyCore: func(string) error {
			return errors.New("bad signature")
		}})
		if readMarker(coreDir, "current") != "" {
			t.Fatal("promoted an unverified core")
		}
		if _, err := os.Stat(filepath.Join(coreDir, "staging", "2.0.0")); !os.IsNotExist(err) {
			t.Fatalf("rejected staged core should be removed, stat err = %v", err)
		}
	})
}

func TestPromoteStagedFilesystemFailures(t *testing.T) {
	ok := func(string) error { return nil }

	t.Run("versions is a file", func(t *testing.T) {
		coreDir := t.TempDir()
		stage(t, coreDir, "2.0.0")
		writeFile(t, filepath.Join(coreDir, "versions"), "not a dir")
		promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir, VerifyCore: ok})
		if readMarker(coreDir, "current") != "" {
			t.Fatal("current written though promotion could not land")
		}
	})

	t.Run("current cannot be written", func(t *testing.T) {
		coreDir := t.TempDir()
		stage(t, coreDir, "2.0.0")
		// A non-empty directory at current makes the atomic rename fail.
		writeFile(t, filepath.Join(coreDir, "current", "x"), "x")
		promoteStaged(Options{Log: testLog(nil), CoreDir: coreDir, VerifyCore: ok})
		if _, err := os.Stat(filepath.Join(coreDir, "previous")); !os.IsNotExist(err) {
			t.Fatalf("previous should not be written when current failed: %v", err)
		}
	})

	t.Run("previous cannot be written", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "current"), "1.0.0\n")
		writeFile(t, filepath.Join(coreDir, "previous", "x"), "x")
		stage(t, coreDir, "2.0.0")
		logs := &syncBuffer{}
		promoteStaged(Options{Log: testLog(logs), CoreDir: coreDir, VerifyCore: ok})
		if got := readMarker(coreDir, "current"); got != "2.0.0" {
			t.Fatalf("current = %q, want 2.0.0 despite the previous failure", got)
		}
		if !strings.Contains(logs.String(), "writing previous failed") {
			t.Fatalf("previous failure not logged:\n%s", logs)
		}
	})
}

func TestRevert(t *testing.T) {
	log := testLog(nil)

	t.Run("no previous", func(t *testing.T) {
		if ok, _ := revert(Options{Log: log, CoreDir: t.TempDir()}, "2.0.0"); ok {
			t.Fatal("reverted with no previous")
		}
	})

	t.Run("previous is the bad version", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "previous"), "2.0.0\n")
		if ok, _ := revert(Options{Log: log, CoreDir: coreDir}, "2.0.0"); ok {
			t.Fatal("reverted onto the version that is crash-looping")
		}
	})

	t.Run("previous has no binary", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "previous"), "1.0.0\n")
		if ok, _ := revert(Options{Log: log, CoreDir: coreDir}, "2.0.0"); ok {
			t.Fatal("reverted to a version with no binary")
		}
	})

	t.Run("flips current and previous", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "versions", "1.0.0", binaryName()), "bin")
		writeFile(t, filepath.Join(coreDir, "previous"), "1.0.0\n")
		writeFile(t, filepath.Join(coreDir, "current"), "2.0.0\n")
		ok, to := revert(Options{Log: log, CoreDir: coreDir}, "2.0.0")
		if !ok || to != "1.0.0" {
			t.Fatalf("revert = %v %q", ok, to)
		}
		if readMarker(coreDir, "current") != "1.0.0" || readMarker(coreDir, "previous") != "2.0.0" {
			t.Fatal("markers not flipped")
		}
	})

	t.Run("current cannot be written", func(t *testing.T) {
		coreDir := t.TempDir()
		writeFile(t, filepath.Join(coreDir, "versions", "1.0.0", binaryName()), "bin")
		writeFile(t, filepath.Join(coreDir, "previous"), "1.0.0\n")
		writeFile(t, filepath.Join(coreDir, "current", "x"), "x")
		if ok, _ := revert(Options{Log: log, CoreDir: coreDir}, "2.0.0"); ok {
			t.Fatal("reported a revert that did not land")
		}
	})
}

func TestWriteStrErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file"), "x")
	if err := writeStr(filepath.Join(dir, "file", "sub", "marker"), "v"); err == nil {
		t.Fatal("writeStr under a regular file should fail")
	}
	if err := writeStr(filepath.Join(dir, "deep", "er", "marker"), "v"); err != nil {
		t.Fatalf("writeStr should create parents: %v", err)
	}
	if readMarker(filepath.Join(dir, "deep", "er"), "marker") != "v" {
		t.Fatal("marker content lost")
	}
}

func TestWriteStrUnwritableDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permission bits do not bind here")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
	if err := writeStr(filepath.Join(dir, "marker"), "v"); err == nil {
		t.Fatal("writeStr into a read-only dir should fail")
	}
}

func TestRunCoreDirUnusable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file"), "x")
	err := Run(
		context.Background(),
		Options{Log: testLog(nil), CoreDir: filepath.Join(dir, "file", "core")},
	)
	if err == nil || !strings.Contains(err.Error(), "preparing") {
		t.Fatalf("want preparing error, got %v", err)
	}
}

func TestRunNoCore(t *testing.T) {
	stubExecutable(t, filepath.Join(t.TempDir(), "weaveboot"), nil)
	err := Run(context.Background(), Options{Log: testLog(nil), CoreDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "no versioned core") {
		t.Fatalf("want no-core error, got %v", err)
	}
}

func TestRunCancelledReturnsNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Options{Log: testLog(nil), CoreDir: t.TempDir()}); err != nil {
		t.Fatalf("Run on a done context = %v", err)
	}
}

// A crash-looping core with nowhere to revert to keeps being retried, and
// a stop that lands during the backoff is honoured promptly.
func TestRunCrashLoopWithoutPrevious(t *testing.T) {
	work := t.TempDir()
	bad := buildFake(t, work, "bad")
	coreDir := filepath.Join(work, "core")
	install(t, coreDir, "2.0.0", bad)
	if err := writeStr(filepath.Join(coreDir, "current"), "2.0.0"); err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Log: testLog(logs), CoreDir: coreDir,
			RevertThreshold: 1, Backoff: time.Hour,
		})
	}()

	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(logs.String(), "cannot revert") {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("never logged the cannot-revert path:\n%s", logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return during backoff after cancel")
	}
}

func TestPromoteStagedRenameFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permission bits do not bind here")
	}
	coreDir := t.TempDir()
	stage(t, coreDir, "2.0.0")
	versions := filepath.Join(coreDir, "versions")
	if err := os.Mkdir(versions, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(versions, 0o700) }) //nolint:errcheck
	logs := &syncBuffer{}
	promoteStaged(
		Options{
			Log:        testLog(logs),
			CoreDir:    coreDir,
			VerifyCore: func(string) error { return nil },
		},
	)
	if !strings.Contains(logs.String(), "promoting staged core failed") {
		t.Fatalf("rename failure not logged:\n%s", logs)
	}
	if readMarker(coreDir, "current") != "" {
		t.Fatal("current written though the promote did not land")
	}
}

// A core that reached readiness before exiting proved the promote good:
// its exits are runtime faults and never count toward a revert.
func TestReadyCoreExitsDoNotCountTowardRevert(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "readyexit.go")
	code := `package main

import "os"

func main() {
	if p := os.Getenv("WEAVE_READY_FILE"); p != "" {
		os.WriteFile(p, []byte("ready\n"), 0o600)
	}
	os.Exit(1)
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(work, "readyexit")
	build := exec.Command("go", "build", "-o", bin, src)
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	coreDir := filepath.Join(work, "core")
	install(t, coreDir, "1.0.0", bin)
	if err := writeStr(filepath.Join(coreDir, "current"), "1.0.0"); err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Log: testLog(logs), CoreDir: coreDir, RevertThreshold: 1, Backoff: time.Millisecond})
	}()
	deadline := time.Now().Add(30 * time.Second)
	for strings.Count(logs.String(), "starting core") < 3 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("core not restarted:\n%s", logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "crash-looping") {
		t.Fatalf("exits after readiness were counted as a crash loop:\n%s", logs)
	}
}
