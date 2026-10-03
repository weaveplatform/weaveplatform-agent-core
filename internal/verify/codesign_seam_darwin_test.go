//go:build !dev

package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCodesign stands in a scripted codesign: --verify exits verifyExit, and
// -d prints display to stderr (where the real one writes it) and exits
// displayExit. The arguments are recorded so the test can check the
// requirement string that would have gone to the real tool.
func fakeCodesign(t *testing.T, verifyExit, displayExit int, display string) string {
	t.Helper()
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> '" + argsLog + "'\n" +
		"case \"$1\" in\n" +
		"--verify) echo 'verify says no' >&2; exit " + itoa(verifyExit) + ";;\n" +
		"-d) printf '%s\\n' '" + display + "' >&2; exit " + itoa(displayExit) + ";;\n" +
		"esac\nexit 99\n"
	bin := filepath.Join(dir, "codesign")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := codesignPath
	codesignPath = bin
	t.Cleanup(func() { codesignPath = old })
	return argsLog
}

func itoa(n int) string { return string(rune('0' + n)) }

func TestCodesignAcceptsTheChainedPinnedTeam(t *testing.T) {
	argsLog := fakeCodesign(t, 0, 0, "Identifier=x\nTeamIdentifier=ABCDE12345")
	if err := codesignVerify("/m", testManifest("ABCDE12345")); err != nil {
		t.Fatalf("pinned, chained signature refused: %v", err)
	}
	args, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	// The anchor clause is what stops a self-signed cert with a forged OU.
	if want := `anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"`; !strings.Contains(
		string(args),
		want,
	) {
		t.Fatalf("requirement not passed to codesign: %s", args)
	}
}

func TestCodesignRefusals(t *testing.T) {
	cases := []struct {
		name                    string
		verifyExit, displayExit int
		display, team, want     string
	}{
		{"malformed team pin", 0, 0, "", "abc", "malformed apple_team_id"},
		{"chain rejected", 1, 0, "", "ABCDE12345", "verify says no"},
		{"display fails", 0, 1, "", "ABCDE12345", "codesign -d failed"},
		{"no team in output", 0, 0, "Identifier=x", "ABCDE12345", "no TeamIdentifier"},
		{"other team", 0, 0, "TeamIdentifier=ZZZZZ99999", "ABCDE12345", `team "ZZZZZ99999"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeCodesign(t, c.verifyExit, c.displayExit, c.display)
			err := codesignVerify("/m", testManifest(c.team))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestDarwinNewVerifierIsCodesign(t *testing.T) {
	if err := newVerifier(nil).Verify("/bin/ls", testManifest("")); err == nil ||
		!strings.Contains(err.Error(), "apple_team_id") {
		t.Fatalf("newVerifier = %v", err)
	}
}
