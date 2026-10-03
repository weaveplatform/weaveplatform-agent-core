// Package keyprotect owns the store master key's at-rest protection. The
// interface is the seam hardware backing slots into: DPAPI machine scope
// on Windows today, a root-only keyfile on unix, Secure Enclave/TPM behind
// the same interface later.
package keyprotect

// Protector seals and unseals the master key.
type Protector interface {
	// Seal wraps the key for storage.
	Seal(key []byte) ([]byte, error)
	// Unseal recovers the key from its stored form.
	Unseal(sealed []byte) ([]byte, error)
}
