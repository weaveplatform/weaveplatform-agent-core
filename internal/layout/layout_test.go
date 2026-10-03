package layout

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/platform"
)

func TestResolvePrecedence(t *testing.T) {
	t.Setenv(EnvStateDir, filepath.Join("env", "root"))
	if got := Resolve(
		filepath.Join("flag", "root"),
	); got.StateDir != filepath.Join(
		"flag",
		"root",
	) {
		t.Fatalf("override lost to env: %v", got)
	}
	l := Resolve("")
	root := filepath.Join("env", "root")
	want := Layout{
		StateDir:   root,
		LogDir:     filepath.Join(root, "logs"),
		RunDir:     filepath.Join(root, "run"),
		StagingDir: filepath.Join(root, "staging"),
		ModulesDir: filepath.Join(root, "modules"),
	}
	if l != want {
		t.Fatalf("Resolve(env) = %+v, want %+v", l, want)
	}

	t.Setenv(EnvStateDir, "")
	p := platform.Paths()
	if got := Resolve(
		"",
	); got.StateDir != p.StateDir || got.ModulesDir != filepath.Join(p.StateDir, "modules") ||
		got.LogDir != p.LogDir || got.RunDir != p.RunDir ||
		got.StagingDir != p.StagingDir {
		t.Fatalf("Resolve(default) = %+v, platform %+v", got, p)
	}
}

func TestEnsureCreatesEveryDirectory(t *testing.T) {
	l := Resolve(filepath.Join(t.TempDir(), "state"))
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{l.StateDir, l.LogDir, l.RunDir, l.StagingDir, l.ModulesDir} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s not created: %v", d, err)
		}
	}
}

func TestEnsureFailsUnderAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(filepath.Join(file, "state")).Ensure(); err == nil {
		t.Fatal("Ensure succeeded beneath a regular file")
	}
}

func TestSocketPaths(t *testing.T) {
	l := Resolve(filepath.Join("r"))
	want := filepath.Join("r", "run", "control.sock")
	if runtime.GOOS == "windows" {
		want = `\\.\pipe\weave-control`
	}
	if got := l.ControlSocket(); got != want {
		t.Fatalf("ControlSocket = %q, want %q", got, want)
	}
	if got := l.ModuleRunDir("m"); got != filepath.Join("r", "run", "modules", "m") {
		t.Fatalf("ModuleRunDir = %q", got)
	}
	if got := l.PolicyFile(); got != filepath.Join("r", "policy.json") {
		t.Fatalf("PolicyFile = %q", got)
	}
}
