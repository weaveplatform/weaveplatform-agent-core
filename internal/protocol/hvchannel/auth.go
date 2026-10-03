package hvchannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

// Authenticating the channel.
//
// The channel is a device node inside the guest and a pair of pipes outside it.
// Anything on the host that can reach those pipes can drive the guest — power it
// off, run a command in it, read its inventory — so without this the boundary is
// "whoever got to the file descriptor first". That is not a boundary.
//
// The guest holds a public key placed there when its image was built; the host
// holds the matching private key in the VM's directory. The guest issues a nonce,
// the host signs it, the guest checks the signature against the key it already
// trusts. Ed25519, as the device identity already uses.
//
// # Per VM, not per host
//
// The keypair belongs to one VM. A process able to drive VM A therefore cannot
// drive VM B, which a host-wide key would have allowed the moment it leaked —
// and the blast radius of a leaked host-wide key is every guest on the machine.
//
// # What is answerable before authentication
//
// Two things, and deliberately only two:
//
//   - The auth handshake itself. A caller that gets a challenge back knows an
//     agent is listening.
//   - PreAuthKind, the guest agent's hello.
//
// Everything else is refused until the signature checks out — fail closed, not
// fail quiet. The narrow exception exists so a caller can tell "wrong key" from
// "no agent at all": those need different responses from an operator, and a
// channel that answered nothing pre-auth would make them identical. Neither
// exception discloses anything the existence of the channel does not: liveness,
// and which agent build is running.

// ControlModule addresses a frame to the channel itself rather than to a module.
// It is a reserved module id — manifest.Validate refuses it — so no module can
// be published under this name and quietly find its traffic intercepted, or
// worse, be in a position to answer for the channel.
const ControlModule = "hvchannel"

// The control frame kinds, all addressed to ControlModule.
const (
	// KindAuthBegin: host → guest. Asks for a challenge. Carries no payload.
	KindAuthBegin = "auth.begin"
	// KindAuthChallenge: guest → host. AuthChallenge.
	KindAuthChallenge = "auth.challenge"
	// KindAuthResponse: host → guest. AuthResponse.
	KindAuthResponse = "auth.response"
	// KindAuthResult: guest → host. AuthResult.
	KindAuthResult = "auth.result"
)

// PreAuthKind is the one module operation answerable before authentication: the
// guest agent's hello. See the package-level note above for why it is exempt and
// why nothing else is.
//
// The literal is the presence capability's hello (weaveplatform-agent-modules,
// address weave.presence). It sits here rather than with the module vocabulary
// because it is a rule about the WIRE — which frames cross an unauthenticated
// channel — and both ends have to agree on it exactly.
const PreAuthKind = "weave.presence.hello"

// GuestweavePreAuthKind is the hello the guestweave host CLIs send. It is
// exempt for the same reason as PreAuthKind: it is how a guestweave host tells
// "wrong key" from "no agent here".
const GuestweavePreAuthKind = "guestweave.presence.hello"

// AllowedBeforeAuth reports whether a module frame of this kind may cross a
// channel that has not authenticated.
//
// Prefix rather than equality because a reply carries the request's kind plus a
// suffix, and an exemption that let the question through but not the answer would
// be an exemption in name only.
func AllowedBeforeAuth(kind string) bool {
	return strings.HasPrefix(kind, PreAuthKind) || strings.HasPrefix(kind, GuestweavePreAuthKind)
}

// NonceSize is 32 bytes: large enough that a nonce is never guessed or repeated,
// which is the entire property being relied on here.
const NonceSize = 32

// AuthChallenge is the guest's nonce. Single-use: the guest forgets it the
// moment a response is checked against it, so a captured response cannot be
// replayed onto a later connection — nor onto the same one.
type AuthChallenge struct {
	Nonce []byte `json:"nonce"`
}

// AuthResponse proves possession of the VM's private key.
//
// PublicKey is sent even though the guest already knows which key it trusts. It
// costs 32 bytes and makes the failure legible: a guest that compares the offered
// key with its own can say "this is a different key" instead of "bad signature",
// and those point at completely different mistakes — the wrong VM directory
// versus a corrupted one.
type AuthResponse struct {
	PublicKey []byte `json:"public_key"` //nolint:tagliatelle // hypervisor channel wire format, shared with host CLIs
	Signature []byte `json:"signature"`
}

// AuthResult is the guest's verdict. Reason is for a human reading a log; a
// caller must branch on OK.
type AuthResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// authDomain separates these signatures from every other use of the same key
// shape. Without it, a signature obtained under one protocol could be presented
// as proof under any other where a party signs a nonce someone else supplied
// with an Ed25519 key. The trailing NUL
// keeps the prefix from running into a nonce that happens to start with printable
// bytes.
var authDomain = []byte("weave-hvchannel-auth\x00")

// SigningMessage is what gets signed: the domain, then the nonce. Both ends must
// build it the same way, which is why neither end builds it itself.
func SigningMessage(nonce []byte) []byte {
	msg := make([]byte, 0, len(authDomain)+len(nonce))
	msg = append(msg, authDomain...)
	return append(msg, nonce...)
}

// NewNonce returns a fresh challenge nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("hvchannel: generating nonce: %w", err)
	}
	return nonce, nil
}

// ErrAuthFailed reports a response that did not prove possession of the trusted
// key. It is deliberately one error for both "wrong key" and "bad signature" at
// the API boundary; the distinction is a log line, not a decision.
var ErrAuthFailed = errors.New("hvchannel: authentication failed")

// Errors Sign returns for inputs it cannot sign.
var (
	ErrBadPrivateKey = errors.New("hvchannel: private key is not ed25519")
	ErrBadNonce      = errors.New("hvchannel: challenge nonce is the wrong size")
	ErrNoPublicHalf  = errors.New("hvchannel: private key has no ed25519 public half")
)

// Sign answers a challenge with the VM's private key.
func Sign(priv ed25519.PrivateKey, challenge AuthChallenge) (AuthResponse, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return AuthResponse{}, ErrBadPrivateKey
	}
	if len(challenge.Nonce) != NonceSize {
		return AuthResponse{}, ErrBadNonce
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return AuthResponse{}, ErrNoPublicHalf
	}
	return AuthResponse{
		PublicKey: bytes.Clone(pub),
		Signature: ed25519.Sign(priv, SigningMessage(challenge.Nonce)),
	}, nil
}

// Verify checks a response against the key the guest trusts and the nonce it
// issued. It returns ErrAuthFailed for anything that does not prove possession,
// with a reason for the log.
//
// The nonce length is checked because a caller that has already consumed its
// nonce must pass a zero one, and a zero-length nonce would otherwise verify a
// signature over the domain alone — replayable forever.
func Verify(trusted ed25519.PublicKey, nonce []byte, resp AuthResponse) (reason string, err error) {
	switch {
	case len(trusted) != ed25519.PublicKeySize:
		return "no trusted key configured", ErrAuthFailed
	case len(nonce) != NonceSize:
		return "no outstanding challenge", ErrAuthFailed
	case !bytes.Equal(resp.PublicKey, trusted):
		return "response offers a different public key than this guest trusts", ErrAuthFailed
	case !ed25519.Verify(trusted, SigningMessage(nonce), resp.Signature):
		return "signature does not match the challenge", ErrAuthFailed
	}
	return "", nil
}
