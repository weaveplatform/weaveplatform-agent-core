package hvchannel

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestAllowedBeforeAuth(t *testing.T) {
	for kind, want := range map[string]bool{
		PreAuthKind:                      true,
		PreAuthKind + ".reply":           true,
		GuestweavePreAuthKind:            true,
		GuestweavePreAuthKind + ".reply": true,
		"weave.power.shutdown":           false,
		"guestweave.power.shutdown":      false,
		"":                               false,
		"weave.presence":                 false,
		"guestweave.presence":            false,
		"weave.presence.inventory":       false,
		KindAuthBegin:                    false,
	} {
		if got := AllowedBeforeAuth(kind); got != want {
			t.Errorf("AllowedBeforeAuth(%q) = %v, want %v", kind, got, want)
		}
	}
}

func TestSignRefusesBadInputs(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(priv[:10], AuthChallenge{Nonce: nonce}); err == nil {
		t.Error("Sign accepted a truncated private key")
	}
	if _, err := Sign(priv, AuthChallenge{Nonce: nonce[:NonceSize-1]}); err == nil {
		t.Error("Sign accepted a short nonce")
	}
}

type failWriter struct{ after int }

var errWrite = errors.New("write failed")

func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errWrite
	}
	w.after--
	return len(p), nil
}

func TestWriteFrameReportsWriteErrors(t *testing.T) {
	// Failing on the header and on the payload are distinct paths.
	for after := range 2 {
		if err := WriteFrame(&failWriter{after: after}, []byte("x")); !errors.Is(err, errWrite) {
			t.Errorf("after %d writes: err = %v", after, err)
		}
	}
	if err := WriteEnvelope(&failWriter{}, Envelope{Module: "m"}); !errors.Is(err, errWrite) {
		t.Errorf("WriteEnvelope: err = %v", err)
	}
}

func TestReadEnvelopeReportsStreamErrors(t *testing.T) {
	if _, err := ReadEnvelope(bytes.NewReader(nil)); err == nil {
		t.Fatal("ReadEnvelope on an empty stream succeeded")
	}
}
