package winsvc

import (
	"os"
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

// RestrictDir must leave exactly SYSTEM and Administrators, protected from
// ProgramData's inherited Users ACEs, and push that down to what is
// already inside — a re-install over a populated state root tightens the
// store and logs too.
func TestRestrictDir(t *testing.T) {
	if _, err := NewManager(); err != nil {
		// Without elevation the test could not delete the directory it
		// has just locked to Administrators.
		t.Skipf("needs an elevated token: %v", err)
	}
	root := filepath.Join(t.TempDir(), "Weave")
	child := filepath.Join(root, "logs", "weaveboot.log")
	if err := os.MkdirAll(filepath.Dir(child), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestrictDir(root); err != nil {
		t.Fatal(err)
	}
	got := daclSDDL(t, root)
	if !strings.HasPrefix(got, "D:P") {
		t.Fatalf("DACL not protected: %s", got)
	}
	for _, sid := range []string{";;;SY)", ";;;BA)"} {
		if !strings.Contains(got, sid) {
			t.Fatalf("DACL %s lacks %s", got, sid)
		}
	}
	if n := strings.Count(got, "(A;"); n != 2 {
		t.Fatalf("DACL has %d allow ACEs, want 2: %s", n, got)
	}
	childDACL := daclSDDL(t, child)
	if strings.Contains(childDACL, ";;;BU)") || strings.Contains(childDACL, ";;;AU)") {
		t.Fatalf("existing child still grants users: %s", childDACL)
	}
}

func TestRestrictDirMissing(t *testing.T) {
	if err := RestrictDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("restricting a missing directory succeeded")
	}
}
