package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	systemio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
)

// The Windows watch is one ReadDirectoryChangesW on the modules directory
// with bWatchSubtree, so module directories are followed as they come and go
// with no per-directory bookkeeping (the inotify watch's job on Linux), and
// every event names the path that changed (unlike kqueue, which needs a
// snapshot to find out). It sees deeper than the other two (versions\<v>\),
// which only means an extra debounced trigger during a lifecycle install.
//
// The read is overlapped so it can be cancelled: a synchronous
// ReadDirectoryChangesW blocks its thread until something changes, and
// closing the handle from another thread is not a documented way to end it.

// watchFilter: names coming and going (which is also how a finished file is
// renamed into place, the way every installer here lands one), and writes in
// place. Not attributes, security or access times: none of them changes what
// discovery reads.
const watchFilter = filesystem.FILE_NOTIFY_CHANGE_FILE_NAME | filesystem.FILE_NOTIFY_CHANGE_DIR_NAME |
	filesystem.FILE_NOTIFY_CHANGE_LAST_WRITE | filesystem.FILE_NOTIFY_CHANGE_SIZE

// watchBuffer is the event buffer's size. Past 64 KiB a directory on a
// network share fails the call, and an overflow is handled anyway (as a
// change). A variable so a test can overflow it.
var watchBuffer = 64 * 1024

// The Win32 errors the watch reads specially.
var (
	errAccessDenied     = syscall.Errno(foundation.ERROR_ACCESS_DENIED)
	errOperationAborted = syscall.Errno(foundation.ERROR_OPERATION_ABORTED)
	errNotifyEnumDir    = syscall.Errno(foundation.ERROR_NOTIFY_ENUM_DIR)
)

// Seams for the tests: the failures the real calls cannot be made to give.
var (
	createEvent = func() (foundation.HANDLE, error) { return threading.CreateEvent(nil, true, false, nil) }
	readChanges = filesystem.ReadDirectoryChangesW
)

func watchOnce(ctx context.Context, dir string, notify func()) error {
	h, err := filesystem.CreateFile(dir,
		uint32(filesystem.FILE_LIST_DIRECTORY),
		// FILE_SHARE_DELETE: the watch must never stop anyone removing or
		// renaming a module directory, or the modules directory itself.
		filesystem.FILE_SHARE_READ|filesystem.FILE_SHARE_WRITE|filesystem.FILE_SHARE_DELETE,
		nil, filesystem.OPEN_EXISTING,
		filesystem.FILE_FLAG_BACKUP_SEMANTICS|filesystem.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return fmt.Errorf("watching %s: %w", dir, err)
	}
	ev, err := createEvent()
	if err != nil {
		foundation.CloseHandle(h) //nolint:errcheck // nothing to do about a failed close
		return fmt.Errorf("watch event: %w", err)
	}

	buf := make([]byte, watchBuffer)
	ov := &systemio.OVERLAPPED{HEvent: ev}

	// Cancellation must reach a read in flight, and must not be lost
	// between one read completing and the next being issued: under mu, a
	// read is only issued while not cancelled, and the cancel finds it. The
	// handles close under mu too, so a cancel arriving as the watch ends
	// never reaches a handle number Windows has since given to someone else.
	var mu sync.Mutex
	cancelled, closed := false, false
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		cancelled = true
		if !closed {
			_ = systemio.CancelIoEx(h, ov)
		}
	})
	defer func() {
		stop()
		mu.Lock()
		defer mu.Unlock()
		closed = true
		foundation.CloseHandle(ev) //nolint:errcheck // nothing to do about a failed close
		foundation.CloseHandle(h)  //nolint:errcheck // as above
	}()

	issue := func() error {
		mu.Lock()
		defer mu.Unlock()
		if cancelled {
			return fmt.Errorf("watch stopped: %w", ctx.Err())
		}
		var n uint32
		if err := readChanges(h, buf, true, watchFilter, &n, ov, 0); err != nil {
			return fmt.Errorf("ReadDirectoryChangesW %s: %w", dir, err)
		}
		return nil
	}

	if err := issue(); err != nil {
		return err
	}
	// Anything that changed before the watch was in place.
	notify()
	for {
		var n uint32
		err := systemio.GetOverlappedResult(h, ov, &n, true)
		switch {
		case errors.Is(err, errOperationAborted):
			return fmt.Errorf("watch stopped: %w", context.Cause(ctx))
		case errors.Is(err, errAccessDenied):
			// The modules directory itself is being deleted: the handle
			// keeps it pending until closed, which this return does.
			return errWatchRootGone
		case errors.Is(err, errNotifyEnumDir):
			// Too many changes for the buffer: some were lost.
			notify()
		case err != nil:
			return fmt.Errorf("reading changes in %s: %w", dir, err)
		case n == 0:
			// The same, reported as an empty result.
			notify()
		default:
			if changedNames(dir, buf[:n]) {
				notify()
			}
		}
		if err := issue(); err != nil {
			return err
		}
	}
}

// changedNames walks a FILE_NOTIFY_INFORMATION list and reports whether any
// entry names a path discovery could read.
//
// A directory "modified" is skipped: NTFS moves a directory's last-write
// time whenever an entry in it is created, renamed or deleted, so every
// staged temporary would otherwise also arrive as a change to the module
// directory holding it. The entries' own events say everything that matters.
func changedNames(root string, buf []byte) bool {
	const header = int(unsafe.Offsetof(filesystem.FILE_NOTIFY_INFORMATION{}.FileName))
	changed := false
	for off := 0; off+header <= len(buf); {
		info := (*filesystem.FILE_NOTIFY_INFORMATION)(
			unsafe.Pointer(&buf[off]),
		) //nolint:gosec // the kernel's record layout
		end := off + header + int(info.FileNameLength)
		if end > len(buf) {
			break
		}
		name := make([]uint16, info.FileNameLength/2)
		for i := range name {
			name[i] = uint16(buf[off+header+2*i]) | uint16(buf[off+header+2*i+1])<<8
		}
		rel := string(utf16.Decode(name))
		if !ignoredPath(rel) &&
			(info.Action != filesystem.FILE_ACTION_MODIFIED || !isDir(filepath.Join(root, rel))) {
			changed = true
		}
		if info.NextEntryOffset == 0 {
			break
		}
		off += int(info.NextEntryOffset)
	}
	return changed
}

func isDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.IsDir()
}

// ignoredPath is a path, relative to the modules directory, under or at a
// name nothing reads: see ignoredName.
func ignoredPath(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if ignoredName(part) {
			return true
		}
	}
	return false
}

// ignoredName is a file something is still writing or keeping aside. A
// finished file is renamed (or File.Replace'd) to a name that is not one of
// these, and that is the event that matters:
//   - <name>.new: agent-modules' module zip installer stages each file
//     beside its destination;
//   - .install-*, and every dot-name: weaveboot's own installer, and the
//     lifecycle manager's .tmp-* staging;
//   - *.tmp and ~*: Windows Installer and most Windows tools' temporaries
//     (an MSI writes ~xxxx.tmp beside what it installs);
//   - .dpkg-*: a tree shared with Linux tooling.
//
// Discovery only opens a module's own names (<id>.exe, module.manifest.json,
// config.json, current, versions), none of which look like these.
func ignoredName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "~") ||
		strings.HasSuffix(lower, ".new") || strings.HasSuffix(lower, ".tmp") ||
		strings.Contains(lower, ".dpkg-")
}
