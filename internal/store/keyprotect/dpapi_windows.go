package keyprotect

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	crypt "github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"
	"golang.org/x/sys/windows/registry"
)

// New returns the platform protector: DPAPI machine scope with secondary
// entropy derived from the machine GUID. Machine scope alone lets ANY
// local process CryptUnprotectData the blob; binding secondary entropy to
// the machine GUID (which is not stored beside store.key) means a stolen
// store.key cannot be unsealed on a different machine, and raises the bar
// for local unseal to also knowing the machine GUID.
func New() Protector { return dpapiProtector{} }

type dpapiProtector struct{}

// Errors dpapi returns before calling into DPAPI.
var (
	errEmptyInput = errors.New("keyprotect: empty input")
	errTooLarge   = errors.New("keyprotect: input too large for a DPAPI blob")
)

const dpapiFlags = crypt.CRYPTPROTECT_UI_FORBIDDEN | crypt.CRYPTPROTECT_LOCAL_MACHINE

// Where the entropy is read from. Vars only so the failure paths can be
// tested; nothing but a test writes them.
var (
	entropyKey   = `SOFTWARE\Microsoft\Cryptography`
	entropyValue = "MachineGuid"
)

// machineEntropy reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
// It is per-install, machine-bound, and not written next to the key.
func machineEntropy() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		entropyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("keyprotect: opening Cryptography key: %w", err)
	}
	defer k.Close()
	guid, _, err := k.GetStringValue(entropyValue)
	if err != nil {
		return nil, fmt.Errorf("keyprotect: reading MachineGuid: %w", err)
	}
	return []byte("weave-store-v1:" + guid), nil
}

// dpapiDescription is stored in the clear inside the sealed blob; it labels
// the blob for anyone inspecting it and plays no part in the protection.
const dpapiDescription = "weave store master key"

func sealOp(in, entB, out *crypt.CRYPT_INTEGER_BLOB) error {
	descr := dpapiDescription
	if err := crypt.CryptProtectData(in, &descr, entB, nil, dpapiFlags, out); err != nil {
		return fmt.Errorf("CryptProtectData: %w", err)
	}
	return nil
}

func unsealOp(in, entB, out *crypt.CRYPT_INTEGER_BLOB) error {
	if err := crypt.CryptUnprotectData(in, nil, entB, nil, dpapiFlags, out); err != nil {
		return fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return nil
}

func (dpapiProtector) Seal(key []byte) ([]byte, error) {
	ent, err := machineEntropy()
	if err != nil {
		return nil, err
	}
	return dpapi(key, ent, sealOp)
}

func (dpapiProtector) Unseal(sealed []byte) ([]byte, error) {
	ent, err := machineEntropy()
	if err != nil {
		return nil, err
	}
	return dpapi(sealed, ent, unsealOp)
}

func dpapi(
	data, entropy []byte,
	op func(in, ent, out *crypt.CRYPT_INTEGER_BLOB) error,
) ([]byte, error) {
	in, err := blob(data)
	if err != nil {
		return nil, err
	}
	ent, err := blob(entropy)
	if err != nil {
		return nil, err
	}
	var out crypt.CRYPT_INTEGER_BLOB
	if err := op(&in, &ent, &out); err != nil {
		return nil, fmt.Errorf("keyprotect: dpapi: %w", err)
	}
	defer func() { _, _ = foundation.LocalFree(foundation.HLOCAL(unsafe.Pointer(out.PbData))) }()
	result := make([]byte, out.CbData)
	copy(result, unsafe.Slice(out.PbData, out.CbData))
	return result, nil
}

// blob describes b to DPAPI, refusing what a CRYPT_INTEGER_BLOB cannot carry.
func blob(b []byte) (crypt.CRYPT_INTEGER_BLOB, error) {
	n := len(b)
	if n == 0 {
		return crypt.CRYPT_INTEGER_BLOB{}, errEmptyInput
	}
	if n > math.MaxUint32 {
		return crypt.CRYPT_INTEGER_BLOB{}, errTooLarge
	}
	return crypt.CRYPT_INTEGER_BLOB{CbData: uint32(n), PbData: &b[0]}, nil
}
