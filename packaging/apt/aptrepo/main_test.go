package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary doubles as a fake gpg: with fakeGPGEnv set it writes a
// placeholder to every --output and fails when its argv contains the
// value of fakeGPGFailEnv. That keeps signing and verification on their
// real code paths without a keyring.
const (
	fakeGPGEnv     = "APTREPO_FAKE_GPG"
	fakeGPGFailEnv = "APTREPO_FAKE_GPG_FAIL"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeGPGEnv) == "1" {
		os.Exit(fakeGPG(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeGPG(args []string) int {
	if fail := os.Getenv(fakeGPGFailEnv); fail != "" {
		for _, a := range args {
			if a == fail {
				fmt.Fprintln(os.Stderr, "fake gpg: refusing", fail)
				return 2
			}
		}
	}
	for i, a := range args {
		if a == "--output" && i+1 < len(args) {
			if err := os.WriteFile(args[i+1], []byte("-----BEGIN PGP-----\n"), 0o644); err != nil {
				return 3
			}
		}
	}
	return 0
}

func useFakeGPG(t *testing.T, failOn string) {
	t.Helper()
	orig := gpgCommand
	gpgCommand = func(args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), fakeGPGEnv+"=1", fakeGPGFailEnv+"="+failOn)
		return cmd
	}
	t.Cleanup(func() { gpgCommand = orig })
}

type arMember struct {
	name string
	data []byte
}

func arArchive(members ...arMember) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(
			&b,
			"%-16s%-12s%-6s%-6s%-8s%-10d`\n",
			m.name+"/",
			"0",
			"0",
			"0",
			"100644",
			len(m.data),
		)
		b.Write(m.data)
		if len(m.data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

func tarOf(files map[string]string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, body := range files {
		tw.WriteHeader(
			&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))},
		) //nolint:errcheck
		tw.Write(
			[]byte(body),
		) //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	return b.Bytes()
}

func gz(data []byte) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(data) //nolint:errcheck
	zw.Close()     //nolint:errcheck
	return b.Bytes()
}

func control(pkg string) string {
	return "Package: " + pkg + "\nVersion: 1.0.0\nArchitecture: arm64\nMaintainer: t <t@example>\nDescription: test\n"
}

// deb builds a minimal real .deb: debian-binary (odd length, so the ar
// padding path is exercised), control.tar.gz, data.tar.gz.
func deb(pkg string) []byte {
	return arArchive(
		arMember{"debian-binary", []byte("2.0\n\n")},
		arMember{
			"control.tar.gz",
			gz(tarOf(map[string]string{"./md5sums": "", "./control": control(pkg)})),
		},
		arMember{"data.tar.gz", gz(tarOf(map[string]string{"./usr/bin/x": "x"}))},
	)
}

func writeDebs(t *testing.T, dir string, debs map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range debs {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func aptrepo(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBuildUnsignedThenVerify(t *testing.T) {
	in, out := t.TempDir(), filepath.Join(t.TempDir(), "repo")
	writeDebs(
		t,
		in,
		map[string][]byte{"b_1.0.0_arm64.deb": deb("b"), "a_1.0.0_arm64.deb": deb("a")},
	)

	code, stdout, stderr := aptrepo("-in", in, "-out", out, "-origin", "test-origin")
	if code != 0 {
		t.Fatalf("build: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "wrote unsigned repository") ||
		!strings.Contains(stdout, "[trusted=yes]") {
		t.Fatalf("unsigned build must say so: %q", stdout)
	}

	pkgs, err := os.ReadFile(filepath.Join(out, "Packages"))
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, flat-repo relative, carrying the control fields and digests.
	if strings.Index(string(pkgs), "Package: a") > strings.Index(string(pkgs), "Package: b") {
		t.Errorf("Packages not sorted:\n%s", pkgs)
	}
	for _, want := range []string{"Filename: ./a_1.0.0_arm64.deb", "Size: ", "MD5sum: ", "SHA1: ", "SHA256: ", "Architecture: arm64"} {
		if !strings.Contains(string(pkgs), want) {
			t.Errorf("Packages lacks %q", want)
		}
	}
	rel, err := os.ReadFile(filepath.Join(out, "Release"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Origin: test-origin", "Label: test-origin", "MD5Sum:", "SHA1:", "SHA256:", " Packages.gz"} {
		if !strings.Contains(string(rel), want) {
			t.Errorf("Release lacks %q", want)
		}
	}

	code, stdout, stderr = aptrepo("-verify", out)
	if code != 0 {
		t.Fatalf("verify: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"repository is unsigned", "2 index digests ok", "2 package digests ok"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("verify output lacks %q: %q", want, stdout)
		}
	}
}

func TestBuildSignedThenVerify(t *testing.T) {
	useFakeGPG(t, "")
	in, out := t.TempDir(), t.TempDir()
	writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})

	code, stdout, stderr := aptrepo("-in", in, "-out", out, "-key", "ABCD")
	if code != 0 {
		t.Fatalf("build: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "wrote signed repository") {
		t.Fatalf("stdout: %q", stdout)
	}
	for _, f := range []string{"InRelease", "Release.gpg", "weave-archive-keyring.asc"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("signing did not produce %s: %v", f, err)
		}
	}
	code, stdout, _ = aptrepo("-verify", out)
	if code != 0 || !strings.Contains(stdout, "InRelease signature ok") {
		t.Fatalf("verify signed: exit %d %q", code, stdout)
	}
}

func TestSigningFailures(t *testing.T) {
	for _, step := range []string{"--clearsign", "--detach-sign", "--export"} {
		t.Run(step, func(t *testing.T) {
			useFakeGPG(t, step)
			in, out := t.TempDir(), t.TempDir()
			writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
			code, _, stderr := aptrepo("-in", in, "-out", out, "-key", "ABCD")
			if code != 1 || !strings.Contains(stderr, "aptrepo: gpg ") {
				t.Fatalf("exit %d %q", code, stderr)
			}
		})
	}
}

// A bad signature must fail verification before any digest is trusted.
func TestVerifyBadSignature(t *testing.T) {
	useFakeGPG(t, "")
	in, out := t.TempDir(), t.TempDir()
	writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
	if code, _, stderr := aptrepo("-in", in, "-out", out, "-key", "K"); code != 0 {
		t.Fatalf("build: %s", stderr)
	}
	useFakeGPG(t, "--verify")
	code, _, stderr := aptrepo("-verify", out)
	if code != 1 || !strings.Contains(stderr, "InRelease signature") {
		t.Fatalf("exit %d %q", code, stderr)
	}
}

func builtRepo(t *testing.T) string {
	t.Helper()
	in, out := t.TempDir(), t.TempDir()
	writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
	if code, _, stderr := aptrepo("-in", in, "-out", out); code != 0 {
		t.Fatalf("build: %s", stderr)
	}
	return out
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		mutate func(t *testing.T, dir string)
		want   string
	}{
		"index changed": {func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "Packages.gz"), "x")
		}, "SHA256 in Release does not match"},
		"deb changed": {func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "a.deb"), "x")
		}, "SHA256 in Packages does not match"},
		"deb missing": {func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, "a.deb")) //nolint:errcheck
		}, "a.deb"},
		"index missing": {func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, "Packages.gz")) //nolint:errcheck
		}, "Packages.gz"},
		"no Release": {func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, "Release")) //nolint:errcheck
		}, "Release"},
		"Release without SHA256": {func(t *testing.T, dir string) {
			overwrite(
				t,
				filepath.Join(dir, "Release"),
				"Origin: x\nMD5Sum:\n d41d8cd98f00b204e9800998ecf8427e 0 Packages\n",
			)
		}, "no SHA256 digests"},
		"no Packages": {func(t *testing.T, dir string) {
			// Release must still check out, so drop Packages from it too.
			rel := readFile(t, filepath.Join(dir, "Release"))
			var kept []string
			for _, l := range strings.Split(rel, "\n") {
				if !strings.HasSuffix(l, " Packages") {
					kept = append(kept, l)
				}
			}
			overwrite(t, filepath.Join(dir, "Release"), strings.Join(kept, "\n"))
			os.Remove(filepath.Join(dir, "Packages")) //nolint:errcheck
		}, "Packages"},
		"Packages empty": {func(t *testing.T, dir string) {
			overwrite(t, filepath.Join(dir, "Packages"), "Package: a\n")
			fixRelease(t, dir)
		}, "lists no packages"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := builtRepo(t)
			c.mutate(t, dir)
			code, _, stderr := aptrepo("-verify", dir)
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, c.want)
			}
		})
	}
}

// fixRelease regenerates Release after a deliberate Packages edit, so the
// test reaches the Packages checks instead of failing at the index digests.
func fixRelease(t *testing.T, dir string) {
	t.Helper()
	if err := writeGzip(
		filepath.Join(dir, "Packages.gz"),
		[]byte(readFile(t, filepath.Join(dir, "Packages"))),
	); err != nil {
		t.Fatal(err)
	}
	rel, err := releaseFile(dir, "weave")
	if err != nil {
		t.Fatal(err)
	}
	overwrite(t, filepath.Join(dir, "Release"), rel)
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func overwrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	overwrite(t, p, readFile(t, p)+s)
}

func TestBuildFailures(t *testing.T) {
	t.Run("no debs", func(t *testing.T) {
		code, _, stderr := aptrepo("-in", t.TempDir(), "-out", t.TempDir())
		if code != 1 || !strings.Contains(stderr, "no .deb files") {
			t.Fatalf("exit %d %q", code, stderr)
		}
	})
	t.Run("bad glob", func(t *testing.T) {
		code, _, _ := aptrepo("-in", "[", "-out", t.TempDir())
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("out under a file", func(t *testing.T) {
		in := t.TempDir()
		writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
		blocker := filepath.Join(t.TempDir(), "f")
		overwrite(t, blocker, "x")
		if code, _, _ := aptrepo("-in", in, "-out", filepath.Join(blocker, "repo")); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("not a deb", func(t *testing.T) {
		in := t.TempDir()
		writeDebs(t, in, map[string][]byte{"junk.deb": []byte("this is not an ar archive")})
		code, _, stderr := aptrepo("-in", in, "-out", t.TempDir())
		if code != 1 || !strings.Contains(stderr, "junk.deb: not an ar archive") {
			t.Fatalf("exit %d %q", code, stderr)
		}
	})
	// Building into the input directory leaves the .debs where they are.
	t.Run("in place", func(t *testing.T) {
		dir := t.TempDir()
		writeDebs(t, dir, map[string][]byte{"a.deb": deb("a")})
		if code, _, stderr := aptrepo("-in", dir, "-out", dir); code != 0 {
			t.Fatalf("exit %d %s", code, stderr)
		}
	})
	t.Run("Packages blocked", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
		if err := os.Mkdir(filepath.Join(out, "Packages"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := aptrepo("-in", in, "-out", out); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("Packages.gz blocked", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
		if err := os.Mkdir(filepath.Join(out, "Packages.gz"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := aptrepo("-in", in, "-out", out); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("Release blocked", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
		if err := os.Mkdir(filepath.Join(out, "Release"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := aptrepo("-in", in, "-out", out); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("deb copy blocked", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeDebs(t, in, map[string][]byte{"a.deb": deb("a")})
		if err := os.Mkdir(filepath.Join(out, "a.deb"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := aptrepo("-in", in, "-out", out); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
}

func TestReleaseFileMissingIndex(t *testing.T) {
	if _, err := releaseFile(t.TempDir(), "weave"); err == nil {
		t.Fatal("releaseFile over a directory with no indexes should fail")
	}
}

func TestFlags(t *testing.T) {
	if code, _, stderr := aptrepo(); code != 2 || !strings.Contains(stderr, "-out is required") {
		t.Fatalf("no -out: exit %d %q", code, stderr)
	}
	if code, _, _ := aptrepo("-bogus"); code != 2 {
		t.Fatalf("bad flag: exit %d", code)
	}
	if code, _, _ := aptrepo("-h"); code != 0 {
		t.Fatalf("-h: exit %d", code)
	}
}

func TestReadControl(t *testing.T) {
	ctl := control("x")
	cases := map[string]struct {
		data    []byte
		want    string
		wantErr string
	}{
		"gzip control": {data: deb("x"), want: ctl},
		"plain tar control": {data: arArchive(
			arMember{"debian-binary", []byte("2.0\n")},
			arMember{"control.tar", tarOf(map[string]string{"control": ctl})},
		), want: ctl},
		"xz control": {data: arArchive(
			arMember{"control.tar.xz", []byte("xz")},
		), wantErr: "unsupported compression"},
		"bad gzip": {data: arArchive(
			arMember{"control.tar.gz", []byte("this is definitely not gzip data")},
		), wantErr: "gzip"},
		"tar without control": {data: arArchive(
			arMember{"control.tar", tarOf(map[string]string{"./postinst": "#!/bin/sh"})},
		), wantErr: "no ./control"},
		"corrupt tar": {data: arArchive(
			arMember{"control.tar", bytes.Repeat([]byte{0xff}, 1024)},
		), wantErr: "tar"},
		"no control member": {data: arArchive(
			arMember{"debian-binary", []byte("2.0\n")},
		), wantErr: "no control member"},
		"short magic":      {data: []byte("!<ar"), wantErr: "EOF"},
		"truncated header": {data: append([]byte("!<arch>\n"), "debian-binary"...), wantErr: "EOF"},
		"bad size": {
			data: append(
				[]byte("!<arch>\n"),
				fmt.Sprintf(
					"%-16s%-12s%-6s%-6s%-8s%-10s`\n",
					"debian-binary/",
					"0",
					"0",
					"0",
					"100644",
					"abc",
				)...),
			wantErr: "bad ar member size",
		},
		"truncated member": {
			data: append(
				[]byte("!<arch>\n"),
				fmt.Sprintf(
					"%-16s%-12s%-6s%-6s%-8s%-10d`\n",
					"debian-binary/",
					"0",
					"0",
					"0",
					"100644",
					100,
				)...),
			wantErr: "EOF",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x.deb")
			overwrite(t, p, string(c.data))
			got, err := readControl(p)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("readControl = %q, %v", got, err)
			}
		})
	}
	if _, err := readControl(filepath.Join(t.TempDir(), "missing.deb")); err == nil {
		t.Fatal("readControl of a missing file should fail")
	}
}

func TestDigestsAndCopyErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := digests(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("digests of a missing file should fail")
	}
	if _, err := digests(dir); err == nil {
		t.Fatal("digests of a directory should fail")
	}
	if err := copyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
		t.Fatal("copyFile from a missing file should fail")
	}
	if _, err := packageStanza(filepath.Join(dir, "missing.deb")); err == nil {
		t.Fatal("packageStanza of a missing file should fail")
	}
}
