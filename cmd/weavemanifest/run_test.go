package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wm(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

const channelJSON = `{"schema":1,"channel":"stable","sequence":7,"generated_at":"2026-08-10T00:00:00Z","expires":"2099-01-01T00:00:00Z","protocol":{"min":1,"max":1},"core":{"version":"0.1.0","artifacts":[]},"modules":[]}`

// chain mints root + signing keys and a signed manifest through the CLI
// verbs, exactly as an operator would.
func chain(t *testing.T) (dir, root, signing, mf string) {
	t.Helper()
	dir = t.TempDir()
	root, signing, mf = filepath.Join(
		dir,
		"root",
	), filepath.Join(
		dir,
		"signing",
	), filepath.Join(
		dir,
		"channel.json",
	)
	if err := os.WriteFile(mf, []byte(channelJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"keygen", "root", root},
		{"keygen", "signing-1", signing},
		{"endorse", root + ".key", signing + ".pub"},
		{"sign", signing + ".key", mf},
	} {
		if code, _, errOut := wm(args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
	}
	return dir, root, signing, mf
}

func TestCLIRoundTrip(t *testing.T) {
	_, root, signing, mf := chain(t)

	code, out, errOut := wm("verify", root+".pub", signing+".pub", mf)
	if code != 0 {
		t.Fatalf("verify: exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, `channel "stable", sequence 7`) {
		t.Fatalf("verify output: %q", out)
	}

	// The private key must not be world-readable: it is the whole chain.
	if fi, err := os.Stat(root + ".key"); err != nil {
		t.Fatal(err)
	} else if mode := fi.Mode().Perm(); mode&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("private key mode %o", mode)
	}

	// Signing with the manifest key where the endorsement belongs (or the
	// reverse) is a different domain and must not verify.
	if code, _, _ := wm("sign", root+".key", signing+".pub"); code != 0 {
		t.Fatal("re-sign failed")
	}
	if code, _, _ := wm("verify", root+".pub", signing+".pub", mf); code == 0 {
		t.Fatal("an endorsement signed in the manifest domain verified")
	}
}

func TestKeygenOutput(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "k")
	code, out, _ := wm("keygen", "my-key", prefix)
	if code != 0 || !strings.Contains(out, `key id "my-key"`) {
		t.Fatalf("keygen: exit %d %q", code, out)
	}
}

func TestVerifyFailures(t *testing.T) {
	dir, root, signing, mf := chain(t)
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(unsigned, []byte(channelJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing root":      {"verify", filepath.Join(dir, "nope"), signing + ".pub", mf},
		"unparseable root":  {"verify", garbage, signing + ".pub", mf},
		"missing signing":   {"verify", root + ".pub", filepath.Join(dir, "nope"), mf},
		"manifest unsigned": {"verify", root + ".pub", signing + ".pub", unsigned},
		"wrong root":        {"verify", signing + ".pub", signing + ".pub", mf},
	}
	for name, args := range cases {
		code, _, errOut := wm(args...)
		if code != 1 || !strings.HasPrefix(errOut, "weavemanifest: ") {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
}

func TestSignFailures(t *testing.T) {
	dir, root, _, mf := chain(t)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notJSON := write("bad.key", "{")
	badB64 := write("b64.key", `{"schema":1,"key_id":"x","private_key":"!!!"}`)
	short := write("short.key", `{"schema":1,"key_id":"x","private_key":"AAAA"}`)

	cases := map[string][]string{
		"missing key":      {"sign", filepath.Join(dir, "nope.key"), mf},
		"key not json":     {"sign", notJSON, mf},
		"key not base64":   {"sign", badB64, mf},
		"key wrong size":   {"endorse", short, mf},
		"missing file":     {"sign", root + ".key", filepath.Join(dir, "nope")},
		"input is a dir":   {"sign", root + ".key", dir},
		"sig is directory": {"sign", root + ".key", mkSigDir(t, dir)},
	}
	for name, args := range cases {
		if code, _, errOut := wm(args...); code != 1 || errOut == "" {
			t.Errorf("%s: exit %d %q", name, code, errOut)
		}
	}
}

// mkSigDir leaves a directory where the signature file must be written.
func mkSigDir(t *testing.T, dir string) string {
	t.Helper()
	f := filepath.Join(dir, "blocked.json")
	if err := os.WriteFile(f, []byte(channelJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f+".sig", 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestKeygenWriteFailures(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := wm("keygen", "k", filepath.Join(dir, "no", "such", "dir", "k")); code != 1 {
		t.Fatalf("keygen into a missing dir: exit %d", code)
	}
	// .pub lands but .key is blocked: the failure must still surface.
	prefix := filepath.Join(dir, "half")
	if err := os.Mkdir(prefix+".key", 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := wm("keygen", "k", prefix); code != 1 {
		t.Fatalf("keygen with blocked .key: exit %d", code)
	}
}

func TestUsageAndVerbs(t *testing.T) {
	if code, _, errOut := wm(); code != 1 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no args: exit %d %q", code, errOut)
	}
	if code, _, errOut := wm("frobnicate"); code != 1 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("unknown verb: exit %d %q", code, errOut)
	}
	for _, verb := range []string{"generate", "promote", "pin"} {
		if code, _, errOut := wm(
			verb,
		); code != 1 ||
			!strings.Contains(errOut, "not yet a local verb") {
			t.Errorf("%s: exit %d %q", verb, code, errOut)
		}
	}
	for _, args := range [][]string{{"keygen"}, {"endorse", "a"}, {"sign"}, {"verify", "a", "b"}} {
		if code, _, errOut := wm(args...); code != 1 || !strings.Contains(errOut, args[0]+" <") {
			t.Errorf("%v: exit %d %q", args, code, errOut)
		}
	}
}
