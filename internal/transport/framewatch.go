package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// errFrameStalled ends a read loop whose peer stopped part-way through a frame.
var errFrameStalled = errors.New("transport: hypervisor channel stalled mid-frame")

// frameStall is how long a frame may go without a byte before the channel is
// taken to have lost its place. A host writes each frame in one go, so mid-frame
// silence is not a slow peer: it is bytes that will never arrive (the macOS
// virtio console has been seen to lose them under bulk traffic), and without a
// reset every later frame is read from the wrong offset and the channel is dead
// until core restarts. Long enough that a paused or heavily loaded VM is not
// reset for being slow; a false reset costs the host one call and a re-auth.
var frameStall = 10 * time.Second

// frameWatch sits between the wire and the frame decoder and follows the
// length-prefixed framing (internal/protocol/hvchannel) byte by byte, so it
// knows whether the stream is between frames or inside one, how far in, and
// when a byte last arrived. It decodes nothing and changes nothing: the decoder
// still reads every byte through it.
type frameWatch struct {
	r io.Reader

	mu       sync.Mutex
	hdr      [4]byte
	hdrHave  int    // header bytes seen of the frame in progress
	need     uint64 // body bytes still to come; meaningful once hdrHave == 4
	declared uint64 // the frame in progress's length
	last     time.Time
	total    uint64
}

func newFrameWatch(r io.Reader) *frameWatch {
	return &frameWatch{r: r, last: time.Now()}
}

func (w *frameWatch) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if n > 0 {
		w.advance(p[:n])
	}
	return n, err //nolint:wrapcheck // the decoder classifies the wire's own error
}

func (w *frameWatch) advance(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last = time.Now()
	w.total += uint64(len(b))
	for len(b) > 0 {
		if w.hdrHave < len(w.hdr) {
			c := copy(w.hdr[w.hdrHave:], b)
			w.hdrHave += c
			b = b[c:]
			if w.hdrHave == len(w.hdr) {
				w.declared = uint64(binary.BigEndian.Uint32(w.hdr[:]))
				w.need = w.declared
				if w.need == 0 {
					w.hdrHave = 0
				}
			}
			continue
		}
		c := min(uint64(len(b)), w.need)
		w.need -= c
		b = b[c:]
		if w.need == 0 {
			w.hdrHave = 0
		}
	}
}

// stalled reports a frame in progress that has had no byte for longer than
// limit, with how far it got for the log.
func (w *frameWatch) stalled(limit time.Duration) (bool, stallInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	info := stallInfo{
		declared: w.declared,
		missing:  w.need,
		idle:     time.Since(w.last),
		total:    w.total,
	}
	if w.hdrHave < len(w.hdr) {
		info.declared, info.missing = 0, uint64(len(w.hdr)-w.hdrHave)
	}
	return w.hdrHave > 0 && info.idle > limit, info
}

type stallInfo struct {
	declared, missing, total uint64
	idle                     time.Duration
}
