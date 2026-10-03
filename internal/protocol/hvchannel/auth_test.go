package hvchannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignedChallengeVerifies(t *testing.T) {
	pub, priv := keypair(t)
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Sign(priv, AuthChallenge{Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := Verify(pub, nonce, resp); err != nil {
		t.Fatalf("verify: %v (%s)", err, reason)
	}
}

func TestVerifyRefusesADifferentKey(t *testing.T) {
	trusted, _ := keypair(t)
	_, otherPriv := keypair(t)
	nonce, _ := NewNonce()

	resp, err := Sign(otherPriv, AuthChallenge{Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	reason, err := Verify(trusted, nonce, resp)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("a well-formed signature from the wrong key verified: %v", err)
	}
	if reason == "" {
		t.Error("no reason given; a log with no reason cannot be acted on")
	}
}

// The replay case, stated the way the guest sees it: the guest consumes its
// nonce, so a captured response arrives with nothing outstanding to check it
// against.
func TestVerifyRefusesAConsumedChallenge(t *testing.T) {
	pub, priv := keypair(t)
	nonce, _ := NewNonce()
	resp, _ := Sign(priv, AuthChallenge{Nonce: nonce})

	if _, err := Verify(pub, nonce, resp); err != nil {
		t.Fatalf("first use should verify: %v", err)
	}
	// The guest clears its nonce after checking one response against it.
	if _, err := Verify(pub, nil, resp); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("a replayed response verified with no outstanding challenge")
	}
}

func TestVerifyRefusesASignatureOverADifferentNonce(t *testing.T) {
	pub, priv := keypair(t)
	signed, _ := NewNonce()
	outstanding, _ := NewNonce()

	resp, _ := Sign(priv, AuthChallenge{Nonce: signed})
	if _, err := Verify(pub, outstanding, resp); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("a signature over another nonce verified")
	}
}

// A zero-length nonce must never be treated as a challenge: a signature over the
// domain alone would be valid forever, which is a permanent skeleton key rather
// than a failed handshake.
func TestVerifyRefusesAnEmptyNonce(t *testing.T) {
	pub, priv := keypair(t)
	resp := AuthResponse{
		PublicKey: bytes.Clone(pub),
		Signature: ed25519.Sign(priv, SigningMessage(nil)),
	}
	if _, err := Verify(pub, nil, resp); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("a signature over an empty nonce verified")
	}
}

func TestVerifyRefusesWhenNoKeyIsTrusted(t *testing.T) {
	_, priv := keypair(t)
	nonce, _ := NewNonce()
	resp, _ := Sign(priv, AuthChallenge{Nonce: nonce})

	if _, err := Verify(nil, nonce, resp); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("a guest with no trusted key accepted a response — fail closed means refusing here")
	}
}

// Domain separation, stated as a property rather than a constant: a signature
// over the bare nonce — which is what another protocol signing a server nonce
// would produce — must not verify here.
func TestSignatureOverTheBareNonceDoesNotVerify(t *testing.T) {
	pub, priv := keypair(t)
	nonce, _ := NewNonce()
	resp := AuthResponse{
		PublicKey: bytes.Clone(pub),
		Signature: ed25519.Sign(priv, nonce),
	}
	if _, err := Verify(pub, nonce, resp); !errors.Is(err, ErrAuthFailed) {
		t.Fatal(
			"a signature over the undomained nonce verified; the domain prefix is not being applied",
		)
	}
}

func TestNoncesDoNotRepeat(t *testing.T) {
	seen := make(map[string]bool, 64)
	for range 64 {
		n, err := NewNonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != NonceSize {
			t.Fatalf("nonce is %d bytes, want %d", len(n), NonceSize)
		}
		if seen[string(n)] {
			t.Fatal("a nonce repeated")
		}
		seen[string(n)] = true
	}
}
