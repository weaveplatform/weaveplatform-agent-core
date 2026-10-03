package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

// authenticatedForTest returns an auth that is already past the handshake, for
// the tests that are about framing and delivery rather than about the gate.
func authenticatedForTest() *channelAuth {
	return &channelAuth{log: slog.New(slog.DiscardHandler), ok: true}
}

// guestEnd wires a peer to one side of a pipe and hands back the host side.
func guestEnd(t *testing.T, keyPath string) (*Mux, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	guestConn, hostConn := net.Pipe()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mux := &Mux{Log: log}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mux.Hypervisor = newHypervisorPeer(
		ctx,
		guestConn,
		log,
		mux.deliver,
		newChannelAuth(log, keyPath),
	)
	return mux, bufio.NewReader(hostConn), bufio.NewWriter(hostConn)
}

func writeKeyFile(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "channel.pub")
	if err := os.WriteFile(
		path,
		[]byte(base64.StdEncoding.EncodeToString(pub)+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return path
}

func send(t *testing.T, w *bufio.Writer, module, kind string, payload any) {
	t.Helper()
	var data []byte
	if payload != nil {
		var err error
		if data, err = json.Marshal(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := hvchannel.WriteEnvelope(
		w,
		hvchannel.Envelope{Module: module, Kind: kind, Data: data},
	); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

func readEnvelope(t *testing.T, r *bufio.Reader) hvchannel.Envelope {
	t.Helper()
	type result struct {
		env hvchannel.Envelope
		err error
	}
	ch := make(chan result, 1)
	go func() {
		env, err := hvchannel.ReadEnvelope(r)
		ch <- result{env, err}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatalf("reading a frame: %v", got.err)
		}
		return got.env
	case <-time.After(5 * time.Second):
		t.Fatal(
			"no frame arrived; the guest answered nothing where it should have refused explicitly",
		)
		return hvchannel.Envelope{}
	}
}

// The happy path, and the only one that ends with a module receiving anything.
func TestHandshakeAdmitsAHostHoldingTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux, hostR, hostW := guestEnd(t, writeKeyFile(t, pub))
	in := mux.Receive(context.Background(), "weave")

	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	challengeEnv := readEnvelope(t, hostR)
	if challengeEnv.Kind != hvchannel.KindAuthChallenge {
		t.Fatalf("expected a challenge, got %q", challengeEnv.Kind)
	}
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(challengeEnv.Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, err := hvchannel.Sign(priv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)

	var result hvchannel.AuthResult
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("authentication refused a host holding the key: %s", result.Reason)
	}

	send(t, hostW, "weave", "weave.power.shutdown", map[string]string{"id": "p1"})
	select {
	case msg := <-in:
		if msg.Kind != "weave.power.shutdown" {
			t.Fatalf("delivered %q", msg.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an authenticated channel did not deliver to the module")
	}
}

// The failure that matters: a peer with the wrong key gets a refusal, and the
// module never sees the operation.
func TestWrongKeyIsRefusedOnEveryOperation(t *testing.T) {
	trustedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	mux, hostR, hostW := guestEnd(t, writeKeyFile(t, trustedPub))
	in := mux.Receive(context.Background(), "weave")

	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, err := hvchannel.Sign(attackerPriv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)

	var result hvchannel.AuthResult
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("a host signing with the wrong key was admitted")
	}

	send(t, hostW, "weave", "weave.power.shutdown", map[string]string{"id": "p1"})
	// The refusal comes back as a control frame rather than silence, so an
	// operator with the wrong key sees a reason instead of a hang.
	refusal := readEnvelope(t, hostR)
	if refusal.Kind != hvchannel.KindAuthResult {
		t.Fatalf("expected a refusal, got %q", refusal.Kind)
	}
	select {
	case msg := <-in:
		t.Fatalf("an unauthenticated peer reached the module with %q", msg.Kind)
	case <-time.After(200 * time.Millisecond):
	}
}

// Hello, and only hello, crosses an unauthenticated channel — that exemption is
// what lets a caller tell "wrong key" from "no agent here".
func TestHelloIsAnsweredBeforeAuthenticationButNothingElseIs(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	mux, hostR, hostW := guestEnd(t, writeKeyFile(t, pub))
	in := mux.Receive(context.Background(), "weave")

	send(t, hostW, "weave", hvchannel.PreAuthKind, map[string]string{"id": "h1"})
	select {
	case msg := <-in:
		if msg.Kind != hvchannel.PreAuthKind {
			t.Fatalf("delivered %q", msg.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hello was not delivered on an unauthenticated channel")
	}

	// And the module's reply is allowed back out, or the exemption would be
	// one-way and therefore useless. Sent from a goroutine because net.Pipe is
	// unbuffered: the write does not complete until the read below starts.
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- mux.Hypervisor.Send(context.Background(), "weave",
			hvchannel.PreAuthKind+".result", []byte(`{"id":"h1"}`))
	}()
	if got := readEnvelope(t, hostR); got.Kind != hvchannel.PreAuthKind+".result" {
		t.Fatalf("read %q", got.Kind)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("the hello reply was blocked outbound: %v", err)
	}

	// An unsolicited event must not leak to a peer that never identified itself.
	if err := mux.Hypervisor.Send(context.Background(), "weave",
		"weave.exec.output", []byte(`{"id":"e1"}`)); err == nil {
		t.Fatal("module output was sent over an unauthenticated channel")
	}
}

// A replayed response cannot re-open a channel: the nonce is consumed on first
// use, whatever the outcome.
func TestReplayedResponseIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := writeKeyFile(t, pub)

	_, hostR, hostW := guestEnd(t, keyPath)
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, _ := hvchannel.Sign(priv, challenge)
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)
	readEnvelope(t, hostR) // the success

	// Same captured response, replayed to a fresh connection — the case that
	// matters, because that is what an attacker who recorded the wire has.
	_, replayR, replayW := guestEnd(t, keyPath)
	send(t, replayW, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)
	var result hvchannel.AuthResult
	if err := json.Unmarshal(readEnvelope(t, replayR).Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("a replayed response authenticated a new connection")
	}
}

// An unprovisioned guest — no key file at all — must authenticate nobody rather
// than everybody. This is the fail-closed case, and the one most likely to be got
// wrong by an "if no key configured, skip the check" shortcut.
func TestGuestWithNoKeyAuthenticatesNobody(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	missing := filepath.Join(t.TempDir(), "channel.pub")

	_, hostR, hostW := guestEnd(t, missing)
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthBegin, nil)
	var challenge hvchannel.AuthChallenge
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &challenge); err != nil {
		t.Fatal(err)
	}
	resp, _ := hvchannel.Sign(priv, challenge)
	send(t, hostW, hvchannel.ControlModule, hvchannel.KindAuthResponse, resp)

	var result hvchannel.AuthResult
	if err := json.Unmarshal(readEnvelope(t, hostR).Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("a guest with no trusted key admitted a caller")
	}
}
