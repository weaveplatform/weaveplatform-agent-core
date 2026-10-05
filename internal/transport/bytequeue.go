package transport

import (
	"errors"
	"io"
	"sync"
)

// errQueueClosed is a read or write on a byteQueue after Close.
var errQueueClosed = errors.New("transport: channel buffer closed")

// byteQueue is a bounded in-memory byte stream between a goroutine that
// drains a device and the frame decoder that reads it. Unlike io.Pipe it
// buffers: the drain keeps taking bytes off the device while the decoder is
// busy — decoding a large frame, delivering it, or waiting on the write lock
// to answer — so the device's own small queue does not fill behind it. When
// this one is full the drain blocks, which is back-pressure to the host, not
// loss.
type byteQueue struct {
	mu       sync.Mutex
	readable sync.Cond
	writable sync.Cond
	buf      []byte
	off      int
	max      int
	err      error // set once: the stream's end, for the reader after the buffer
	closed   bool
}

func newByteQueue(limit int) *byteQueue {
	q := &byteQueue{max: limit}
	q.readable.L = &q.mu
	q.writable.L = &q.mu
	return q
}

// Write appends p, waiting for room as needed. It fails only once the queue
// is closed.
func (q *byteQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for !q.closed && q.err == nil && len(q.buf)-q.off >= q.max {
			q.writable.Wait()
		}
		if q.closed || q.err != nil {
			return written, errQueueClosed
		}
		if q.off > 0 && q.off >= len(q.buf)/2 {
			q.buf = append(q.buf[:0], q.buf[q.off:]...)
			q.off = 0
		}
		n := min(len(p), q.max-(len(q.buf)-q.off))
		q.buf = append(q.buf, p[:n]...)
		p = p[n:]
		written += n
		q.readable.Broadcast()
	}
	return written, nil
}

// Read takes what is buffered, waiting for at least one byte. Once the stream
// has ended (finish) it returns the rest, then the stream's error.
func (q *byteQueue) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for !q.closed && q.err == nil && q.off == len(q.buf) {
		q.readable.Wait()
	}
	if q.closed {
		return 0, errQueueClosed
	}
	if q.off == len(q.buf) {
		return 0, q.err
	}
	n := copy(p, q.buf[q.off:])
	q.off += n
	q.writable.Broadcast()
	return n, nil
}

// finish ends the stream: the reader gets what is buffered, then err (io.EOF
// for nil).
func (q *byteQueue) finish(err error) {
	if err == nil {
		err = io.EOF
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err == nil {
		q.err = err
	}
	q.readable.Broadcast()
	q.writable.Broadcast()
}

// Close discards the buffer and fails every pending and later call.
func (q *byteQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.buf, q.off = nil, 0
	q.readable.Broadcast()
	q.writable.Broadcast()
	return nil
}
