package provision

import (
	"fmt"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
)

// anchorSDDL is the Windows reading of 0644 root: full control for SYSTEM and
// Administrators, read for Users, and protected (P) so nothing inherited from
// the directory — ProgramData lets Users create and write there — applies.
const anchorSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

// secureAnchor gives the anchor anchorSDDL. It is set on the staged file
// before the link that publishes it, so the anchor never exists with a looser
// ACL; the link is the same file, and carries it.
func secureAnchor(path string) error {
	var sd security.PSECURITY_DESCRIPTOR
	if err := authorization.ConvertStringSecurityDescriptorToSecurityDescriptor(
		anchorSDDL, authorization.SDDL_REVISION_1, &sd, nil); err != nil {
		return fmt.Errorf("parsing SDDL: %w", err)
	}
	// LocalFree's binding reports NULL — its success value — as failure.
	defer func() { _, _ = foundation.LocalFree(foundation.HLOCAL(sd)) }()
	var present, defaulted foundation.BOOL
	var dacl *security.ACL
	if err := security.GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted); err != nil {
		return fmt.Errorf("reading DACL: %w", err)
	}
	if rc := authorization.SetNamedSecurityInfo(path, authorization.SE_FILE_OBJECT,
		security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, dacl, nil); rc != 0 {
		return fmt.Errorf("setting the anchor's ACL: %w", syscall.Errno(rc))
	}
	return nil
}
