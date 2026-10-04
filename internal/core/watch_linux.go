package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchRetry is how long the watch waits before trying again when the modules
// directory is missing or the watch fails; the periodic rescan covers the gap.
var watchRetry = 5 * time.Second

var errWatchRootGone = errors.New("modules directory removed or moved")

// The events that can change what a module directory holds. IN_CLOSE_WRITE
// rather than IN_MODIFY: one event per finished write, not one per write(2)
// of a 20 MB binary. IN_MOVED_TO is how dpkg (and the lifecycle manager's
// markers) land a finished file.
const watchMask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_CLOSE_WRITE | unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR

// watchModules calls notify for every change inotify reports in dir or in any
// module directory directly under it, until ctx ends. notify is the reload
// trigger, which debounces: a package install's burst of events is one pass.
func watchModules(ctx context.Context, log *slog.Logger, dir string, notify func()) {
	logged := false
	for ctx.Err() == nil {
		err := watchOnce(ctx, dir, notify)
		if ctx.Err() != nil {
			return
		}
		// Whatever ended the watch may itself be a change (the directory
		// went away, or came back).
		notify()
		if !logged {
			log.Warn("module directory watch unavailable; retrying", "dir", dir, "err", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRetry):
		}
	}
}

func watchOnce(ctx context.Context, dir string, notify func()) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify: %w", err)
	}
	// Through os.File, so the read parks in the runtime poller and closing
	// the file on ctx end wakes it.
	f := os.NewFile(uintptr(fd), "inotify")
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer func() {
		if stop() {
			f.Close()
		}
	}()

	w := &dirWatch{fd: fd, root: dir, names: map[int32]string{}, wds: map[string]int32{}}
	rootWD, err := unix.InotifyAddWatch(fd, dir, watchMask)
	if err != nil {
		return fmt.Errorf("watching %s: %w", dir, err)
	}
	w.rootWD = int32(rootWD) //nolint:gosec // G115: a watch descriptor is an int32 on the wire
	w.addSubdirs()
	// Anything that changed before the watches were in place.
	notify()

	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	for {
		n, err := f.Read(buf)
		if err != nil {
			return fmt.Errorf("reading inotify: %w", err)
		}
		changed, gone := w.consume(buf[:n])
		if changed {
			notify()
		}
		if gone {
			return errWatchRootGone
		}
	}
}

// dirWatch tracks the watch on the modules directory and one per module
// directory under it, adding and dropping those as directories come and go.
type dirWatch struct {
	fd     int
	root   string
	rootWD int32
	names  map[int32]string
	wds    map[string]int32
}

func (w *dirWatch) addSubdirs() {
	entries, err := os.ReadDir(w.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			w.add(e.Name())
		}
	}
}

func (w *dirWatch) add(name string) {
	if _, ok := w.wds[name]; ok {
		return
	}
	wd, err := unix.InotifyAddWatch(w.fd, filepath.Join(w.root, name), watchMask)
	if err != nil {
		// Gone already, or not a directory: the reload that follows sees
		// whatever is really there.
		return
	}
	w.wds[name] = int32(wd)   //nolint:gosec // G115: see rootWD
	w.names[int32(wd)] = name //nolint:gosec // G115: see rootWD
}

func (w *dirWatch) drop(name string) {
	if wd, ok := w.wds[name]; ok {
		_, _ = unix.InotifyRmWatch(w.fd, uint32(wd)) //nolint:gosec // G115: from InotifyAddWatch
		delete(w.wds, name)
		delete(w.names, wd)
	}
}

// consume walks a read's worth of events. changed: one of them may change a
// module; gone: the modules directory itself went away.
func (w *dirWatch) consume(buf []byte) (changed, gone bool) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		ev := (*unix.InotifyEvent)(
			unsafe.Pointer(&buf[off]),
		) //nolint:gosec // the kernel's event layout
		end := off + unix.SizeofInotifyEvent + int(ev.Len)
		if end > len(buf) {
			break
		}
		name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:end]), "\x00")
		off = end

		mask := ev.Mask
		switch {
		case mask&unix.IN_Q_OVERFLOW != 0:
			// Events were lost: rewatch whatever is there now and reread.
			w.addSubdirs()
			changed = true
			continue
		case ev.Wd == w.rootWD:
			if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
				return true, true
			}
			if mask&unix.IN_ISDIR != 0 {
				switch {
				case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
					w.add(name)
				case mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
					w.drop(name)
				}
			}
		case mask&unix.IN_IGNORED != 0:
			// The kernel dropped a module directory's watch (it was
			// removed); forget it so a directory recreated under the same
			// name is watched again.
			if n, ok := w.names[ev.Wd]; ok {
				delete(w.wds, n)
				delete(w.names, ev.Wd)
			}
			continue
		}
		if ignoredName(name) {
			continue
		}
		changed = true
	}
	return changed, false
}

// ignoredName is a file dpkg is still writing or keeping aside. dpkg unpacks
// each file as <name>.dpkg-new and renames it into place, atomically, and the
// rename is the event that matters; the .dpkg-new itself is never a file
// discovery would read. Waking a reload for it would only race the rename.
// (.dpkg-tmp, .dpkg-old, .dpkg-dist and .dpkg-bak are dpkg's too.)
func ignoredName(name string) bool {
	return strings.Contains(name, ".dpkg-")
}
