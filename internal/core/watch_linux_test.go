package core

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Lost events are a reason to reread everything.
func TestWatchQueueOverflow(t *testing.T) {
	w := &dirWatch{root: t.TempDir(), names: map[int32]string{}, wds: map[string]int32{}}
	buf := make([]byte, unix.SizeofInotifyEvent)
	ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
	ev.Mask = unix.IN_Q_OVERFLOW
	ev.Wd = -1
	if changed, gone := w.consume(buf); !changed || gone {
		t.Fatalf("overflow = %v, %v", changed, gone)
	}
	// A truncated event is not read past.
	if changed, _ := w.consume(buf[:unix.SizeofInotifyEvent-1]); changed {
		t.Fatal("read a truncated event")
	}
}
