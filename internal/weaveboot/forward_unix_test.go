//go:build !windows

package weaveboot

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// buildHupCore builds a fake core that records each SIGHUP it receives in
// WEAVE_HUP_FILE, as weave-agent turns SIGHUP into a module reload.
func buildHupCore(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "hupcore.go")
	code := `package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, os.Interrupt)
	if p := os.Getenv("WEAVE_READY_FILE"); p != "" {
		os.WriteFile(p, []byte("1.0.0\n"), 0o600)
	}
	for {
		select {
		case <-hup:
			f, _ := os.OpenFile(os.Getenv("WEAVE_HUP_FILE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			f.WriteString("hup\n")
			f.Close()
		case <-term:
			return
		}
	}
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "hupcore")
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build hupcore: %v\n%s", err, out)
	}
	return bin
}

// SIGHUP reaches core through weaveboot — systemd's ExecReload signals
// weaveboot, its main pid — and core keeps running: forwarding is not a
// restart, and SIGTERM handling is unchanged by it.
func TestWeavebootForwardsSIGHUP(t *testing.T) {
	work := t.TempDir()
	coreDir := filepath.Join(work, "core")
	install(t, coreDir, "1.0.0", buildHupCore(t, work))
	writeStr(filepath.Join(coreDir, "current"), "1.0.0")
	hupFile := filepath.Join(work, "hup")
	t.Setenv("WEAVE_HUP_FILE", hupFile)

	forward := make(chan os.Signal, 1)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			Log: log, CoreDir: coreDir, StableAfter: time.Hour,
			VerifyCore: func(string) error { return nil },
			Forward:    forward,
		})
	}()
	if !waitForFile(t, filepath.Join(coreDir, "ready"), 30*time.Second) {
		t.Fatal("core never wrote its readiness marker")
	}
	forward <- syscall.SIGHUP
	if !waitForFile(t, hupFile, 10*time.Second) {
		t.Fatal("core never received the forwarded SIGHUP")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("weaveboot returned error: %v", err)
	}
}
