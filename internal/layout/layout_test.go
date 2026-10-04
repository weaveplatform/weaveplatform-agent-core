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
		ExecDir:    filepath.Join(root, "exec"),
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
		got.StagingDir != p.StagingDir || got.ExecDir != filepath.Join(p.StateDir, "exec") {
		t.Fatalf("Resolve(default) = %+v, platform %+v", got, p)
	}
}

func TestEnsureCreatesEveryDirectory(t *testing.T) {
	l := Resolve(filepath.Join(t.TempDir(), "state"))
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{l.StateDir, l.LogDir, l.RunDir, l.StagingDir, l.ModulesDir, l.ExecDir} {
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
	if got := l.ModuleExecDir("m"); got != filepath.Join("r", "exec", "m") {
		t.Fatalf("ModuleExecDir = %q", got)
	}
	if got := l.PolicyFile(); got != filepath.Join("r", "policy.json") {
		t.Fatalf("PolicyFile = %q", got)
	}
}

// Staged binaries must never follow RunDir: on Linux that is /run, mounted
// noexec, so a module staged there cannot be exec'd. ExecDir stays under
// StateDir in both the platform layout and an overridden one.
func TestExecDirIsUnderStateNotRun(t *testing.T) {
	t.Setenv(EnvStateDir, "")
	for _, l := range []Layout{Resolve(""), Resolve(filepath.Join("o", "state"))} {
		if filepath.Dir(l.ExecDir) != l.StateDir {
			t.Fatalf("ExecDir %s is not directly under StateDir %s", l.ExecDir, l.StateDir)
		}
		if rel, err := filepath.Rel(l.RunDir, l.ExecDir); err == nil && filepath.IsLocal(rel) {
			t.Fatalf("ExecDir %s is under RunDir %s", l.ExecDir, l.RunDir)
		}
	}
}

// The mode table is the security model: data private, and only the
// directories a dropped module passes through search-only for others.
func TestDirModes(t *testing.T) {
	l := Resolve(filepath.Join("r"))
	want := map[string]os.FileMode{
		l.StateDir:   0o711,
		l.LogDir:     0o700,
		l.RunDir:     0o711,
		l.StagingDir: 0o700,
		l.ModulesDir: 0o700,
		l.ExecDir:    0o711,
	}
	got := l.dirs()
	if len(got) != len(want) {
		t.Fatalf("dirs() = %d entries, want %d", len(got), len(want))
	}
	if got[0].path != l.StateDir {
		t.Fatalf("StateDir must come first so its mode is set before its children: %+v", got)
	}
	for _, d := range got {
		if want[d.path] != d.mode {
			t.Fatalf("%s mode %04o, want %04o", d.path, d.mode, want[d.path])
		}
	}
}
