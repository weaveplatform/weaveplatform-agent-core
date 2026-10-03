// Package identity owns who this device is: the keypair, the device id, and
// per-module credential scoping. The Provider is the seam hardware backing
// (Secure Enclave, TPM) slots into; v1 is a software Ed25519 key persisted in
// the encrypted store. Identity is local: nothing outside the machine assigns
// it.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
)

// storeNamespace is the core-owned store namespace for identity state.
// Dotted, so no module id can collide with it.
const storeNamespace = "core.identity"

// Provider is the identity seam. Software today; hardware-backed
// implementations replace the key handling.
type Provider struct {
	Log *slog.Logger
	// Store persists the keypair and any recorded device id, encrypted.
	Store hostserv.StoreBackend

	mu       sync.Mutex
	priv     ed25519.PrivateKey
	deviceID string
	tenant   string
}

// ErrCredentialsUnsupported is Credential's answer: core issues no scoped
// credentials.
var ErrCredentialsUnsupported = errors.New("identity: scoped credentials are not yet implemented")

// identityState is the persisted record. Tenant is only ever read back: state
// written by an earlier core may carry one.
type identityState struct {
	DeviceID string `json:"device_id"` //nolint:tagliatelle // persisted format: existing state uses snake_case
	Tenant   string `json:"tenant"`
	// PrivateKey is the Ed25519 seed+pub, base64. The store encrypts at
	// rest; this field never leaves the store namespace.
	PrivateKey string `json:"private_key"` //nolint:tagliatelle // persisted format: existing state uses snake_case
}

// Init loads or creates the keypair and the device id. Call once at startup.
func (p *Provider) Init() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	raw, found, err := p.Store.Get(context.Background(), storeNamespace, "state")
	if err != nil {
		return fmt.Errorf("identity: loading state: %w", err)
	}
	if found {
		var st identityState
		if err := json.Unmarshal(raw, &st); err == nil {
			key, err := base64.StdEncoding.DecodeString(st.PrivateKey)
			if err == nil && len(key) == ed25519.PrivateKeySize {
				p.priv = ed25519.PrivateKey(key)
				p.deviceID = st.DeviceID
				p.tenant = st.Tenant
				if p.deviceID != "" {
					p.Log.Info("identity loaded", "device_id", p.deviceID, "tenant", p.tenant)
					return nil
				}
				// A keypair from a core that predates derived ids: give it one
				// now, from the key it already has, so it never changes again.
				p.deviceID = deriveDeviceID(p.priv)
				p.Log.Info("device id derived", "device_id", p.deviceID)
				return p.saveLocked()
			}
		}
		p.Log.Warn("discarding corrupt identity state")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("identity: generating keypair: %w", err)
	}
	p.priv = priv
	p.deviceID = deriveDeviceID(priv)
	p.Log.Info("identity created", "device_id", p.deviceID)
	return p.saveLocked()
}

// deriveDeviceID names the device after its own key: stable for as long as the
// keypair lives, needing no server to assign it, and unrelated to anything a
// clone or a reinstall would share (a new key is a new device).
func deriveDeviceID(priv ed25519.PrivateKey) string {
	sum := sha256.Sum256(
		priv.Public().(ed25519.PublicKey),
	) // ed25519.PrivateKey.Public always returns ed25519.PublicKey
	return "device-" + hex.EncodeToString(sum[:16])
}

func (p *Provider) saveLocked() error {
	st := identityState{
		DeviceID:   p.deviceID,
		Tenant:     p.tenant,
		PrivateKey: base64.StdEncoding.EncodeToString(p.priv),
	}
	// The private key is meant to be in this record: it is written only to
	// core's encrypted store, under core's own namespace.
	raw, err := json.Marshal(st) //nolint:gosec // G117: persisting the key is this record's purpose
	if err != nil {
		return fmt.Errorf("identity: encoding state: %w", err)
	}
	if err := p.Store.Put(context.Background(), storeNamespace, "state", raw); err != nil {
		return fmt.Errorf("identity: saving state: %w", err)
	}
	return nil
}

// WhoAmI implements hostserv.IdentityBackend. The id is persistent once Init
// has run; ephemeral is reported only for a provider that was never
// initialised, which core never runs.
func (p *Provider) WhoAmI(_ context.Context) (string, bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deviceID, p.deviceID == "", p.tenant
}

// Credential implements hostserv.IdentityBackend. It fails closed: until
// there are real, verifiable, issuer-signed token semantics (with
// core deciding the granted subset, never echoing the request), minting a
// forgeable token that merely looks scoped and expiring is worse than
// none — it invites something downstream to trust it. Returning an error
// keeps that contract honest.
func (p *Provider) Credential(
	_ context.Context,
	module string,
	scopes []string,
) (string, int64, []string, error) {
	return "", 0, nil, ErrCredentialsUnsupported
}

// Enrolled reports, for the control surface, whether the device has its
// persistent id (true once Init has run).
func (p *Provider) Enrolled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deviceID != ""
}
