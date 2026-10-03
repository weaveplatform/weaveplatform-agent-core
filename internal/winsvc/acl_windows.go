package winsvc

import (
	"fmt"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
)

// stateRootSDDL is the Windows reading of the 0700 the unix layout enforces
// (layout.Ensure): full control for SYSTEM and Administrators, inherited by
// everything below, and protected (P) so the permissive ACL ProgramData
// hands down — Users may read and create there — no longer flows in.
const stateRootSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// RestrictDir replaces dir's DACL with stateRootSDDL. SetNamedSecurityInfo
// propagates the inheritable ACEs to existing children, so a state root
// that already holds a store and logs is tightened as a whole.
func RestrictDir(dir string) error {
	var sd security.PSECURITY_DESCRIPTOR
	if err := authorization.ConvertStringSecurityDescriptorToSecurityDescriptor(
		stateRootSDDL, authorization.SDDL_REVISION_1, &sd, nil); err != nil {
		return fmt.Errorf("parsing SDDL: %w", err)
	}
	// LocalFree's binding reports NULL — its success value — as failure,
	// so its result is not checked.
	defer func() { _, _ = foundation.LocalFree(foundation.HLOCAL(sd)) }()
	var present, defaulted foundation.BOOL
	var dacl *security.ACL
	if err := security.GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted); err != nil {
		return fmt.Errorf("reading DACL: %w", err)
	}
	if rc := authorization.SetNamedSecurityInfo(dir, authorization.SE_FILE_OBJECT,
		security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, dacl, nil); rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}
