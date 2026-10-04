package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The macOS watch is kqueue EVFILT_VNODE: a bare BSD kernel interface, so
// x/sys/unix rather than the house bindings (CLAUDE.md). FSEvents, which the
// bindings do carry, was the alternative and is the wrong fit here: it is a
// daemon's coalesced, latency-delayed report delivered through a C callback
// on a dispatch queue, where kqueue is the kernel telling this process
// directly, and the debounce downstream already does the coalescing.
//
// kqueue watches vnodes, not names, and an event on a directory says only that
// its entries changed, not which. So the watch keeps a snapshot — each entry's
// name and inode, in the modules directory and in each module directory — and
// a directory event counts only if the snapshot changed in a way that matters:
// an entry that is not a temporary name appeared, went, or was replaced (a
// rename over `current`, or over a binary, gives the name a new inode). Files
// directly in a module directory are watched too, for a write in place, which
// changes no directory. Deeper levels (versions/<v>/) are not watched, as on
// Linux: a lifecycle install flips `current` last, and the periodic rescan is
// the backstop for anything else.

// Directory and file events that can change what discovery would read.
const (
	kqDirFlags  = unix.NOTE_WRITE | unix.NOTE_DELETE | unix.NOTE_RENAME | unix.NOTE_REVOKE | unix.NOTE_ATTRIB | unix.NOTE_LINK
	kqFileFlags = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_DELETE | unix.NOTE_RENAME | unix.NOTE_ATTRIB
	kqGoneFlags = unix.NOTE_DELETE | unix.NOTE_RENAME | unix.NOTE_REVOKE
	// kqWake is the EVFILT_USER ident that ends a blocked kevent.
	kqWake = 0
)

func watchOnce(ctx context.Context, dir string, notify func()) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return fmt.Errorf("kqueue: %w", err)
	}
	unix.CloseOnExec(kq)
	w := &kqWatch{kq: kq, root: dir, nodes: map[string]*kqNode{}, byFD: map[int]*kqNode{}}

	// kevent blocks in the kernel, out of the runtime poller's reach, so
	// cancellation is a user event on the same queue. The mutex keeps the
	// trigger off a queue already closed — and off whatever kqueue might by
	// then have reused its descriptor number.
	var mu sync.Mutex
	closed := false
	defer func() {
		mu.Lock()
		closed = true
		w.closeAll()
		unix.Close(kq)
		mu.Unlock()
	}()
	if _, err := unix.Kevent(kq, []unix.Kevent_t{{
		Ident: kqWake, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR,
	}}, nil, nil); err != nil {
		return fmt.Errorf("kqueue wake event: %w", err)
	}
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			_, _ = unix.Kevent(kq, []unix.Kevent_t{{
				Ident: kqWake, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER,
			}}, nil, nil)
		}
	})
	defer stop()

	rootNode, err := w.open(dir, true)
	if err != nil {
		return fmt.Errorf("watching %s: %w", dir, err)
	}
	w.rootFD = rootNode.fd
	w.sync()
	// Anything that changed before the watches were in place.
	notify()

	events := make([]unix.Kevent_t, 64)
	for {
		n, err := unix.Kevent(kq, nil, events, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reading kqueue: %w", err)
		}
		fileChanged := false
		for _, ev := range events[:n] {
			if ev.Filter == unix.EVFILT_USER {
				return fmt.Errorf("watch stopped: %w", ctx.Err())
			}
			fd := int(ev.Ident) //nolint:gosec // G115: the ident is the descriptor kqueue was given
			if fd == w.rootFD && ev.Fflags&kqGoneFlags != 0 {
				return errWatchRootGone
			}
			if node, ok := w.byFD[fd]; ok && !node.dir {
				fileChanged = true
			}
		}
		if w.sync() || fileChanged {
			notify()
		}
	}
}

// kqWatch is the set of open vnodes the queue watches and the snapshot it
// compares against.
type kqWatch struct {
	kq     int
	root   string
	rootFD int
	// nodes by path, other than the root; byFD maps an event back.
	nodes map[string]*kqNode
	byFD  map[int]*kqNode
	// snap is every relevant entry, by path relative to root, and its inode.
	snap map[string]uint64
}

type kqNode struct {
	fd  int
	ino uint64
	dir bool
}

// open watches path. O_EVTONLY: for notifications only, so the watch never
// keeps a volume from unmounting.
func (w *kqWatch) open(path string, dir bool) (*kqNode, error) {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fstat: %w", err)
	}
	flags := uint32(kqFileFlags)
	if dir {
		flags = kqDirFlags
	}
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{{
		Ident:  uint64(fd), //nolint:gosec // G115: a descriptor is non-negative
		Filter: unix.EVFILT_VNODE,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: flags,
	}}, nil, nil); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("kevent: %w", err)
	}
	node := &kqNode{fd: fd, ino: st.Ino, dir: dir}
	w.byFD[fd] = node
	return node, nil
}

func (w *kqWatch) close(path string) {
	if node, ok := w.nodes[path]; ok {
		unix.Close(node.fd)
		delete(w.byFD, node.fd)
		delete(w.nodes, path)
	}
}

func (w *kqWatch) closeAll() {
	for path := range w.nodes {
		w.close(path)
	}
	for fd := range w.byFD {
		unix.Close(fd)
		delete(w.byFD, fd)
	}
}

// sync rereads the tree, brings the watches into line with it, and reports
// whether anything a reload would care about changed since the last sync.
func (w *kqWatch) sync() bool {
	now := map[string]uint64{}
	want := map[string]bool{} // path -> is a directory
	entries, _ := os.ReadDir(w.root)
	for _, e := range entries {
		if ignoredName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		now[e.Name()] = inode(info)
		if !e.IsDir() {
			continue
		}
		mdir := filepath.Join(w.root, e.Name())
		want[mdir] = true
		sub, _ := os.ReadDir(mdir)
		for _, f := range sub {
			if ignoredName(f.Name()) {
				continue
			}
			fi, err := f.Info()
			if err != nil {
				continue
			}
			now[filepath.Join(e.Name(), f.Name())] = inode(fi)
			if fi.Mode().IsRegular() {
				want[filepath.Join(mdir, f.Name())] = false
			}
		}
	}
	for path := range w.nodes {
		if _, ok := want[path]; !ok {
			w.close(path)
		}
	}
	for path, dir := range want {
		rel, _ := filepath.Rel(w.root, path)
		if node, ok := w.nodes[path]; ok && node.ino == now[rel] {
			continue
		}
		w.close(path)
		if node, err := w.open(path, dir); err == nil {
			w.nodes[path] = node
		}
	}
	changed := !sameSnapshot(w.snap, now)
	w.snap = now
	return changed
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*unix.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func sameSnapshot(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// ignoredName is a file something is still writing or keeping aside: every
// dot-name (the lifecycle manager's .tmp-* staging, AppleDouble ._* files,
// .DS_Store, an installer's hidden staging), and dpkg's .dpkg-* names for a
// tree shared with Linux tooling. Discovery only ever opens a module's own
// file names, none of which start with a dot; a finished file is renamed to
// one, and that rename is what the watch reports.
func ignoredName(name string) bool {
	return strings.HasPrefix(name, ".") || strings.Contains(name, ".dpkg-")
}
