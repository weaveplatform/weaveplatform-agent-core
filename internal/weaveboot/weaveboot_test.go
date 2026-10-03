package weaveboot

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildFake builds a fake core: "good" sleeps until signalled, "bad"
// exits 1 immediately.
func buildFake(t *testing.T, dir, kind string) string {
	t.Helper()
	src := filepath.Join(dir, kind+".go")
	var code string
	if kind == "good" {
		code = `package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	<-ch
}
`
	} else {
		code = "package main\n\nfunc main() { panic(\"broken core\") }\n"
	}
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, kind)
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", kind, err, out)
	}
	return bin
}

func install(t *testing.T, coreDir, version, bin string) {
	t.Helper()
	dst := filepath.Join(coreDir, "versions", version)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, binaryName()), data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// buildSignalCore builds a fake core that writes its WEAVE_READY_FILE on
// start (the readiness signal) and, on SIGTERM or os.Interrupt (CTRL_BREAK
// on Windows), writes a "graceful" marker
// before exiting 0 — so the test can prove weaveboot terminates core
// gracefully, not with an abrupt kill.
func buildSignalCore(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "signalcore.go")
	code := `package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// The handler goes in before readiness is signalled: the test stops core
	// the moment it sees the marker, and a signal that beat the handler would
	// take the default action and kill the process (on Windows, CTRL_BREAK).
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	if p := os.Getenv("WEAVE_READY_FILE"); p != "" {
		os.WriteFile(p, []byte("1.0.0\n"), 0o600)
	}
	<-ch
	if p := os.Getenv("WEAVE_GRACE_FILE"); p != "" {
		os.WriteFile(p, []byte("graceful\n"), 0o600)
	}
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "signalcore")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build signalcore: %v\n%s", err, out)
	}
	return bin
}

// TestWeavebootStopsCoreGracefully proves weaveboot stops core through its
// shutdown path (SIGTERM on unix, CTRL_BREAK → os.Interrupt on Windows), not
// a hard kill, when its own context is cancelled — and that core's readiness
// marker is observed on the way up.
func TestWeavebootStopsCoreGracefully(t *testing.T) {
	work := t.TempDir()
	core := buildSignalCore(t, work)
	coreDir := filepath.Join(work, "core")
	install(t, coreDir, "1.0.0", core)
	writeStr(filepath.Join(coreDir, "current"), "1.0.0")

	graceFile := filepath.Join(work, "grace")
	t.Setenv("WEAVE_GRACE_FILE", graceFile) // inherited by core via runOnce

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Log: log, CoreDir: coreDir, StableAfter: time.Hour,
			VerifyCore: func(string) error { return nil },
		})
	}()

	// Wait for core to come up (its readiness marker appears).
	readyFile := filepath.Join(coreDir, "ready")
	if !waitForFile(t, readyFile, 30*time.Second) {
		cancel()
		t.Fatal("core never wrote its readiness marker")
	}

	// Cancel weaveboot: it must signal core, which writes the grace marker.
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("weaveboot returned error: %v", err)
	}
	if _, err := os.Stat(graceFile); err != nil {
		t.Fatalf("core was not stopped gracefully (no SIGTERM handler ran): %v", err)
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestStagedPromoteAndCrashLoopRevert(t *testing.T) {
	work := t.TempDir()
	good := buildFake(t, work, "good")
	bad := buildFake(t, work, "bad")

	coreDir := filepath.Join(work, "core")
	// v1 (good) is installed and current.
	install(t, coreDir, "1.0.0", good)
	writeStr(filepath.Join(coreDir, "current"), "1.0.0")
	// v2 (broken) is staged, as an updater would leave it.
	stage := filepath.Join(coreDir, "staging", "2.0.0")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(bad) //nolint:errcheck
	if err := os.WriteFile(filepath.Join(stage, binaryName()), data, 0o755); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Log:             log,
			CoreDir:         coreDir,
			StableAfter:     5 * time.Second,
			RevertThreshold: 3,
			Backoff:         50 * time.Millisecond,
			VerifyCore:      func(string) error { return nil }, // test verifier
		})
	}()

	// The staged broken 2.0.0 is promoted, crash-loops, and weaveboot
	// reverts to 1.0.0, which stays up.
	deadline := time.Now().Add(45 * time.Second)
	reverted := false
	for time.Now().Before(deadline) {
		cur, err := os.ReadFile(filepath.Join(coreDir, "current"))
		if err == nil && string(cur) == "1.0.0\n" {
			// Reverted. Give the good core a moment to be running.
			if prev, err := os.ReadFile(
				filepath.Join(coreDir, "previous"),
			); err == nil &&
				len(prev) > 0 {
				reverted = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !reverted {
		t.Fatal("weaveboot never reverted to 1.0.0")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("weaveboot returned error: %v", err)
	}
}

// Under the SCM weaveboot has no stderr for core to inherit; whatever core
// writes must land in the Output the service gave it, or a core that fails
// at startup leaves no trace anywhere.
func TestCoreOutputGoesToOptionsOutput(t *testing.T) {
	work := t.TempDir()
	coreDir := filepath.Join(work, "core")
	install(t, coreDir, "1.0.0", buildFake(t, work, "bad"))
	writeStr(filepath.Join(coreDir, "current"), "1.0.0")

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Log: testLog(nil), CoreDir: coreDir, Backoff: time.Hour, Output: out,
			VerifyCore: func(string) error { return nil },
		})
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(out.String(), "broken core") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if !strings.Contains(out.String(), "broken core") {
		t.Fatalf("core's output did not reach Options.Output: %q", out.String())
	}
}
