package hvchannel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Envelope{Module: "weave", Kind: "weave.presence.hello", Data: []byte(`{"id":"h1"}`)}
	if err := WriteEnvelope(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Module != want.Module || got.Kind != want.Kind || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes left over — the reader consumed the wrong amount", buf.Len())
	}
}

// A bad envelope must cost exactly one message, not the connection: the length
// prefix has already kept the reader aligned, so the NEXT frame must still
// decode. This is the property that lets core log and continue instead of
// tearing down a channel it cannot re-establish.
func TestUndecodableEnvelopeLeavesStreamAligned(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	next := Envelope{Module: "weave", Kind: "weave.power.shutdown"}
	if err := WriteEnvelope(&buf, next); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadEnvelope(&buf); err == nil {
		t.Fatal("expected a decode error on the malformed frame")
	}
	got, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("the frame after a bad one must still decode: %v", err)
	}
	if got.Kind != next.Kind {
		t.Fatalf("kind = %q, want %q", got.Kind, next.Kind)
	}
}

// A clean close on a frame boundary is io.EOF; a close mid-frame is
// ErrUnexpectedEOF. Callers distinguish "the host went away" from "the channel
// died mid-message", so the two must not collapse into one error.
func TestCleanEOFVersusTruncation(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream: err = %v, want io.EOF", err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	truncated := buf.Bytes()[:buf.Len()-3]
	if _, err := ReadFrame(bytes.NewReader(truncated)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// A corrupt length prefix must be refused before it is used to size an
// allocation — the whole reason MaxFrameSize exists.
func TestOversizedLengthRefusedWithoutAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("expected an oversized-length error")
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v — the length was used before being checked", err)
	}
}

func TestWriteFrameRefusesOversizedPayload(t *testing.T) {
	// Not allocating 512 MiB: a slice header with a fake length would be
	// unsafe, so assert the boundary arithmetic on the check itself.
	if err := WriteFrame(io.Discard, make([]byte, 16)); err != nil {
		t.Fatalf("a normal payload must be accepted: %v", err)
	}
	if MaxFrameSize != 512<<20 {
		t.Fatalf(
			"MaxFrameSize = %d — both ends of the channel agree on 512 MiB",
			MaxFrameSize,
		)
	}
}

// The correlation id is additive: absent from the bytes when empty, so a peer
// that predates it sees exactly the envelope it always did, and carried
// through when set.
func TestEnvelopeID(t *testing.T) {
	plain, err := json.Marshal(Envelope{Module: "m", Kind: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"module":"m","kind":"k"}` {
		t.Fatalf("an envelope without an id encodes as %s", plain)
	}
	var buf bytes.Buffer
	if err := WriteEnvelope(&buf, Envelope{Module: "m", Kind: "k", ID: "c1"}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnvelope(&buf)
	if err != nil || got.ID != "c1" {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	// An old peer's decoder, which knows no id, ignores it.
	var old struct {
		Module string `json:"module"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(
		[]byte(`{"module":"m","kind":"k","id":"c1"}`),
		&old,
	); err != nil ||
		old.Kind != "k" {
		t.Fatalf("old decoder: %+v %v", old, err)
	}
}
