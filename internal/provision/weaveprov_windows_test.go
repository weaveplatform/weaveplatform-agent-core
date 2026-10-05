package provision

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
)

func daclSDDL(t *testing.T, path string) string {
	t.Helper()
	var sd security.PSECURITY_DESCRIPTOR
	if rc := authorization.GetNamedSecurityInfo(path, authorization.SE_FILE_OBJECT,
		security.DACL_SECURITY_INFORMATION, nil, nil, nil, nil, &sd); rc != 0 {
		t.Fatalf("GetNamedSecurityInfo(%s) = %d", path, rc)
	}
	defer foundation.LocalFree(foundation.HLOCAL(sd)) //nolint:errcheck
	var str foundation.PWSTR
	if err := authorization.ConvertSecurityDescriptorToStringSecurityDescriptor(sd,
		authorization.SDDL_REVISION_1, security.DACL_SECURITY_INFORMATION, &str, nil); err != nil {
		t.Fatal(err)
	}
	defer foundation.LocalFree(foundation.HLOCAL(unsafe.Pointer(str))) //nolint:errcheck
	return win32.UTF16ToString(str)
}

// anchorDACL is the file's DACL as SDDL, less the AI (auto-inherited) flag
// Windows adds when it applies a protected DACL: the ACEs and the protection
// are what is being checked.
func anchorDACL(t *testing.T, path string) string {
	t.Helper()
	return strings.Replace(daclSDDL(t, path), "D:PAI(", "D:P(", 1)
}

// The anchor as installed on NTFS: the hard link publishes the staged file,
// which carries the protected ACL it was given before the link; a second
// install finds the link taken and replaces nothing; no staged file is left.
func TestInstallOnNTFS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "weave")
	path := filepath.Join(dir, "channel.pub")
	key, b64 := newKey(t)
	installed, err := install(path, key)
	if err != nil || !installed {
		t.Fatalf("install = %v, %v", installed, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != b64+"\n" {
		t.Fatalf("anchor = %q, %v", got, err)
	}
	if got := anchorDACL(t, path); got != anchorSDDL {
		t.Fatalf("anchor DACL %s, want %s", got, anchorSDDL)
	}
	other, _ := newKey(t)
	if installed, err := install(path, other); err != nil || installed {
		t.Fatalf("second install = %v, %v", installed, err)
	}
	if got, _ := os.ReadFile(path); string(got) != b64+"\n" {
		t.Fatal("the anchor was replaced")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left in %s: %v", dir, entries)
	}
}

// diskpart runs one diskpart script.
func diskpart(t *testing.T, lines ...string) error {
	t.Helper()
	script := filepath.Join(t.TempDir(), "diskpart.txt")
	if err := os.WriteFile(script, []byte(strings.Join(lines, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("diskpart", "/s", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("diskpart %v: %w\n%s", lines, err, out)
	}
	return nil
}

// freeLetter is a drive letter nothing is mounted on, from Z down.
func freeLetter(t *testing.T) string {
	t.Helper()
	mask, err := logicalDrives()
	if mask == 0 {
		t.Fatalf("GetLogicalDrives: %v", err)
	}
	for i := 25; i >= 3; i-- {
		if mask&(1<<i) == 0 {
			return string(rune('A' + i))
		}
	}
	t.Skip("no free drive letter")
	return ""
}

// The whole Windows path against a real volume: a virtual disk formatted
// with the label WEAVEPROV holding weave\channel.pub, first attached
// read-write (refused: anyone could have written it), then read-only
// (installed). This is the shape the guestweave hosts attach. It needs
// diskpart, so an elevated token; CI's Windows runner sets
// WEAVE_TEST_WEAVEPROV=1 to run it.
func TestRealProvisioningVolume(t *testing.T) {
	if os.Getenv("WEAVE_TEST_WEAVEPROV") != "1" {
		t.Skip(
			"set WEAVE_TEST_WEAVEPROV=1 on an elevated Windows host to attach a real WEAVEPROV disk",
		)
	}
	// The long form of the path: the virtual disk service matches a disk by
	// the path it was attached under, and the runner's temporary directory is
	// an 8.3 short name (RUNNER~1) that a later session would not match.
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vhd := filepath.Join(tmp, "weaveprov.vhdx")
	letter := freeLetter(t)
	if err := diskpart(t,
		fmt.Sprintf(`create vdisk file="%s" maximum=32 type=expandable`, vhd),
		fmt.Sprintf(`select vdisk file="%s"`, vhd),
		"attach vdisk",
		"create partition primary",
		"format fs=ntfs label=WEAVEPROV quick",
		"assign letter="+letter,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := diskpart(
			t,
			fmt.Sprintf(`select vdisk file="%s"`, vhd),
			"detach vdisk",
		); err != nil {
			t.Log(err)
		}
	})
	root := letter + `:\`
	key, b64 := newKey(t)
	if err := os.MkdirAll(filepath.Join(root, "weave"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "weave", "channel.pub"),
		[]byte(b64+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	anchor := filepath.Join(t.TempDir(), "weave", "channel.pub")
	p := &Provisioner{Log: quiet(), AnchorPath: anchor}
	if out, err := p.Once(); out != Refused || !errors.Is(err, errNotReadOnly) {
		t.Fatalf("read-write WEAVEPROV: %v, %v", out, err)
	}

	if err := diskpart(t,
		fmt.Sprintf(`select vdisk file="%s"`, vhd),
		"detach vdisk",
		"attach vdisk readonly",
		"select partition 1",
		"assign letter="+letter+" noerr",
	); err != nil {
		t.Fatal(err)
	}
	if out, err := p.Once(); out != Installed || err != nil {
		t.Fatalf("read-only WEAVEPROV: %v, %v", out, err)
	}
	if got, err := os.ReadFile(anchor); err != nil || string(got) != b64+"\n" {
		t.Fatalf("anchor %q, %v; want the volume's key %x", got, err, key)
	}
	if got := anchorDACL(t, anchor); got != anchorSDDL {
		t.Fatalf("anchor DACL %s, want %s", got, anchorSDDL)
	}
	if out, _ := p.Once(); out != AnchorPresent {
		t.Fatalf("second pass: %v", out)
	}
}
