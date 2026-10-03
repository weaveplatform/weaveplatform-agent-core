//go:build !windows

package keyprotect

// New returns the platform protector. On unix the key is stored as-is in
// a 0600 file owned by core's user — filesystem permissions are the gate
// until Secure Enclave (Zone C) backing lands behind this interface.
func New() Protector { return fileProtector{} }

type fileProtector struct{}

func (fileProtector) Seal(key []byte) ([]byte, error)      { return key, nil }
func (fileProtector) Unseal(sealed []byte) ([]byte, error) { return sealed, nil }
