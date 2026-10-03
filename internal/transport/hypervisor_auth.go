package transport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// The guest end of channel authentication.
//
// Everything the host can ask of a guest travels this wire — power it off, run a
// command in it, read its addresses — so the question "who is on the other end"
// has to be answered before any of it is honoured. The guest holds a public key
// placed in its image at build time; the host holds the private half in the VM's
// directory. See internal/protocol/hvchannel for the handshake and why the key is
// per VM rather than per host.
//
// Fail closed. A guest with no key file authenticates nobody and answers nothing
// but hello — which is the correct behaviour for an image that was never
// provisioned, because the alternative is a guest that anyone can drive.

// channelAuth is one connection's authentication state. A new connection starts
// unauthenticated with no outstanding challenge; both are per-connection, so
// nothing learned from one connection carries to the next.
type channelAuth struct {
	log     *slog.Logger
	trusted ed25519.PublicKey

	mu    sync.Mutex
	nonce []byte
	ok    bool
}

// newChannelAuth loads the trusted key. A missing or malformed key file is not an
// error at this level: it produces an auth that refuses everything, and says so
// loudly once, rather than a core that fails to start. A guest that cannot
// authenticate its host is still worth running — it just cannot be driven.
func newChannelAuth(log *slog.Logger, path string) *channelAuth {
	a := &channelAuth{log: log}
	if path == "" {
		path = DefaultChannelKeyPath()
	}
	key, err := loadChannelKey(path)
	switch {
	case err != nil:
		log.Warn("hypervisor channel will authenticate nobody: no usable key",
			"path", path, "err", err)
	default:
		a.trusted = key
		log.Info("hypervisor channel trust anchor loaded", "path", path)
	}
	return a
}

// fresh returns a new connection's state under the same trust anchor: nothing
// proved on an earlier connection carries over, so a host that reconnects has
// to authenticate again.
func (a *channelAuth) fresh() *channelAuth {
	return &channelAuth{log: a.log, trusted: a.trusted}
}

// authenticated reports whether this connection's peer has proved the key.
func (a *channelAuth) authenticated() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ok
}

// errChannelKeySize refuses a decoded channel key that is not an Ed25519 public
// key.
var errChannelKeySize = errors.New("channel key is not an Ed25519 public key")

// loadChannelKey reads a base64 Ed25519 public key.
//
// One encoding, not several: a key file that is silently accepted in two formats
// is a key file that can be got subtly wrong, and the failure mode here is a
// guest that trusts the wrong party rather than one that reports a parse error.
func loadChannelKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the channel key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"%w: key is %d bytes, want %d",
			errChannelKeySize,
			len(key),
			ed25519.PublicKeySize,
		)
	}
	return ed25519.PublicKey(key), nil
}

// DefaultChannelKeyPath is where a guest image places the host's public key. It
// is an OS path rather than anything under the state directory because the key is
// provisioned when the image is built — it is not state core owns, and core must
// not be able to rewrite the thing that decides who may command it.
func DefaultChannelKeyPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return programData + `\weave\channel.pub`
	}
	return "/etc/weave/channel.pub"
}

// allows reports whether a module frame may cross this connection now.
func (a *channelAuth) allows(kind string) bool {
	if hvchannel.AllowedBeforeAuth(kind) {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ok
}

// handle processes one control frame and returns the reply to send, if any.
//
// The reply is returned rather than sent from here so that all writing stays with
// the peer's single writer. Two places writing to this wire is the failure the
// whole channel design exists to avoid.
func (a *channelAuth) handle(kind string, data []byte) (replyKind string, reply any) {
	switch kind {
	case hvchannel.KindAuthBegin:
		nonce, err := hvchannel.NewNonce()
		if err != nil {
			a.log.Error("hypervisor channel: could not generate a challenge", "err", err)
			return hvchannel.KindAuthResult, hvchannel.AuthResult{Reason: "no challenge available"}
		}
		a.mu.Lock()
		// A second begin replaces the outstanding nonce. That is deliberate: it
		// lets a host retry a handshake it lost track of, and it cannot help an
		// attacker, who would still have to sign the new nonce.
		a.nonce = nonce
		a.mu.Unlock()
		return hvchannel.KindAuthChallenge, hvchannel.AuthChallenge{Nonce: nonce}

	case hvchannel.KindAuthResponse:
		var resp hvchannel.AuthResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return hvchannel.KindAuthResult, hvchannel.AuthResult{Reason: "malformed response"}
		}
		a.mu.Lock()
		nonce := a.nonce
		// Consume the nonce whatever the outcome. A failed attempt must not
		// leave a live challenge behind for the next attempt to guess against,
		// and a successful one must not be replayable.
		a.nonce = nil
		trusted := a.trusted
		a.mu.Unlock()

		if reason, err := hvchannel.Verify(trusted, nonce, resp); err != nil {
			a.log.Warn("hypervisor channel: authentication refused", "reason", reason)
			return hvchannel.KindAuthResult, hvchannel.AuthResult{Reason: reason}
		}
		a.mu.Lock()
		a.ok = true
		a.mu.Unlock()
		a.log.Info("hypervisor channel authenticated")
		return hvchannel.KindAuthResult, hvchannel.AuthResult{OK: true}

	default:
		// Includes the guest→host kinds arriving in the wrong direction. Not an
		// error worth a reply; a host that sends them is broken, not hostile.
		a.log.Warn("hypervisor channel: unknown control frame", "kind", kind)
		return "", nil
	}
}
