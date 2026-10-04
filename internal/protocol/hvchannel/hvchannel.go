// Package hvchannel is the framing and addressing format of the hypervisor
// channel — the single byte pipe (virtio-serial / vsock / HvSocket) between
// core running inside a guest and the host tooling outside it.
//
// BOTH ends must encode identically and there is no negotiation to catch a
// mismatch: the guest end is core's transport peer, the host end is the CLI's
// client, and a field renamed on one side would simply stop matching on the
// other. This is core's own copy; the host end imports the sdk's hvchannel,
// built from the same source. The two must stay byte-for-byte compatible, and
// a change here is a change to both (docs/decisions/0001).
//
// This is a different wire from the module protocol (weave/agent/v1). Adding it
// is additive and does not move the protocol integer — see PROTOCOL.md.
//
// # The single-owner rule
//
// The format has NO resynchronisation. A frame is a length and then exactly
// that many bytes; a reader that loses its place cannot find the next boundary,
// so a desynchronised stream stays broken rather than degrading. Therefore each
// end must have exactly ONE reader and serialise its writes. Callers are
// responsible for that discipline — this package deliberately provides no
// locking, because a mutex here would imply it was safe to hand the same
// connection to two owners.
package hvchannel

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize bounds a single frame at 512 MiB, so a corrupt or hostile
// length prefix cannot drive an unbounded allocation.
const MaxFrameSize = 512 << 20

// Envelope is the on-wire addressing header: which module a message is for, the
// operation kind, and the opaque payload. The peer is implicit — everything on
// this wire is to or from the hypervisor.
//
// Data is deliberately opaque here: the feature vocabulary that fills it (the
// guestwire kinds) is product logic and lives with the modules, not in the
// platform API.
//
// ID is an optional correlation the sender chooses. Core never reads Data, so
// a reply core makes on a module's behalf — delivery.failed — can only be
// matched to the host's pending call by something outside Data: core echoes
// ID on every control reply to a frame that carried one. It is omitted when
// empty, so a peer built before it existed neither sends nor sees it, and a
// decoder that does not know the field ignores it.
type Envelope struct {
	Module string `json:"module"`
	Kind   string `json:"kind"`
	Data   []byte `json:"data,omitempty"`
	ID     string `json:"id,omitempty"`
}

// ErrFrameTooLarge reports a frame over MaxFrameSize, written or read.
var ErrFrameTooLarge = errors.New("hvchannel: frame too large")

// WriteFrame writes one length-prefixed frame: 4-byte big-endian length, then
// the payload. It does not flush; a buffered writer is the caller's to flush,
// because only the caller knows whether more frames are coming.
func WriteFrame(w io.Writer, payload []byte) error {
	size := len(payload)
	if size < 0 || size > MaxFrameSize {
		return fmt.Errorf("%w: %d", ErrFrameTooLarge, size)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(size))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("hvchannel: writing frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("hvchannel: writing frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame. It returns io.EOF only when the
// stream ends cleanly on a frame boundary; a truncated frame reports
// io.ErrUnexpectedEOF, which is the caller's signal that the channel died
// mid-message rather than closing.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// A clean end on a frame boundary is io.EOF itself, unwrapped: callers
		// tell a closed channel from a broken one by it.
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("hvchannel: reading frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, fmt.Errorf(
			"%w: frame length %d exceeds max %d",
			ErrFrameTooLarge,
			n,
			MaxFrameSize,
		)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("hvchannel: reading frame: %w", err)
	}
	return buf, nil
}

// WriteEnvelope marshals env and writes it as one frame. Prefer this over
// hand-marshalling: it is the encoding both ends must agree on.
func WriteEnvelope(w io.Writer, env Envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("hvchannel: encoding envelope: %w", err)
	}
	return WriteFrame(w, payload)
}

// ReadEnvelope reads one frame and decodes it.
//
// A decode failure is reported with the frame intact rather than as a fatal
// stream error: the length prefix has already kept the reader aligned, so one
// unreadable envelope costs one message, not the connection. Callers should log
// and continue.
func ReadEnvelope(r io.Reader) (Envelope, error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return Envelope{}, fmt.Errorf(
			"hvchannel: undecodable envelope (%d bytes): %w",
			len(payload),
			err,
		)
	}
	return env, nil
}
