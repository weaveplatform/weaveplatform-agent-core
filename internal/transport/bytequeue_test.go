package transport

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"time"
)

// A writer much faster than the reader loses nothing and reorders nothing:
// it waits for room instead.
func TestByteQueueNeverDropsUnderAFastWriter(t *testing.T) {
	q := newByteQueue(1000)
	want := make([]byte, 1<<20)
	for i := range want {
		want[i] = byte(rand.IntN(256))
	}
	go func() {
		for p := want; len(p) > 0; {
			n := min(len(p), 1+rand.IntN(5000))
			if _, err := q.Write(p[:n]); err != nil {
				return
			}
			p = p[n:]
		}
		q.finish(nil)
	}()
	var got bytes.Buffer
	buf := make([]byte, 333)
	for {
		n, err := q.Read(buf)
		got.Write(buf[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("stream differs: %d bytes of %d", got.Len(), len(want))
	}
}

func TestByteQueueEndAndClose(t *testing.T) {
	q := newByteQueue(8)
	if n, err := q.Read(nil); n != 0 || err != nil {
		t.Fatal("an empty read must not block or fail")
	}
	errBoom := errors.New("boom")
	q.Write([]byte("ab")) //nolint:errcheck
	q.finish(errBoom)
	q.finish(io.EOF) // the first end wins
	buf := make([]byte, 8)
	if n, err := q.Read(buf); n != 2 || err != nil {
		t.Fatalf("buffered bytes come before the end: %d %v", n, err)
	}
	if _, err := q.Read(buf); !errors.Is(err, errBoom) {
		t.Fatalf("end: %v", err)
	}
	if _, err := q.Write([]byte("c")); !errors.Is(err, errQueueClosed) {
		t.Fatalf("write after end: %v", err)
	}

	q = newByteQueue(2)
	q.Write([]byte("xy")) //nolint:errcheck
	blocked := make(chan error, 1)
	go func() {
		_, err := q.Write([]byte("z"))
		blocked <- err
	}()
	time.Sleep(20 * time.Millisecond)
	q.Close()
	if err := <-blocked; !errors.Is(err, errQueueClosed) {
		t.Fatalf("a writer waiting for room: %v", err)
	}
	if _, err := q.Read(buf); !errors.Is(err, errQueueClosed) {
		t.Fatalf("read after close: %v", err)
	}
}
