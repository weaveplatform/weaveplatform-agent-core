package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var errSeqInjected = errors.New("injected")

func seqPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), SequenceFile)
}

func readMark(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReadSeqFile(t *testing.T) {
	path := seqPath(t)
	if n, err := readSeqFile(path); err != nil || n != 0 {
		t.Fatalf("missing file = %d, %v; want 0", n, err)
	}
	for content, want := range map[string]uint64{"9": 9, "12\n": 12, " 3 \r\n": 3} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if n, err := readSeqFile(path); err != nil || n != want {
			t.Fatalf("%q = %d, %v; want %d", content, n, err, want)
		}
	}
	// Malformed is an error, never 0: empty (a truncated write), not a
	// number, negative, overflowing.
	for _, content := range []string{"", "\n", "seven", "-1", "99999999999999999999999"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if n, err := readSeqFile(path); !errors.Is(err, errSeqMalformed) || n != 0 {
			t.Fatalf("%q = %d, %v; want errSeqMalformed", content, n, err)
		}
	}
	// Unreadable (a directory where the file should be).
	dir := seqPath(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeqFile(dir); err == nil {
		t.Fatal("read a directory as a mark")
	}
}

func TestWriteSeqFileIsAtomic(t *testing.T) {
	path := seqPath(t)
	if err := writeSeqFile(path, 41); err != nil {
		t.Fatal(err)
	}
	if err := writeSeqFile(path, 42); err != nil {
		t.Fatal(err)
	}
	if got := readMark(t, path); got != "42\n" {
		t.Fatalf("mark = %q", got)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("left behind %v", entries)
	}
}

// failingTemp is a temp file whose steps fail on demand.
type failingTemp struct {
	*os.File
	write, chmod, sync, close error
}

func (f failingTemp) Write(b []byte) (int, error) {
	if f.write != nil {
		return 0, f.write
	}
	return f.File.Write(b)
}

func (f failingTemp) Chmod(m os.FileMode) error {
	if f.chmod != nil {
		return f.chmod
	}
	return f.File.Chmod(m)
}

func (f failingTemp) Sync() error {
	if f.sync != nil {
		return f.sync
	}
	return f.File.Sync()
}

func (f failingTemp) Close() error {
	err := f.File.Close()
	if f.close != nil {
		return f.close
	}
	return err
}

// A write that fails at any step leaves the old mark exactly as it was, and no
// temp file beside it.
func TestWriteSeqFileFailuresKeepTheOldMark(t *testing.T) {
	origCreate, origRename, origSync := seqCreateTemp, seqRename, seqSyncDir
	t.Cleanup(func() { seqCreateTemp, seqRename, seqSyncDir = origCreate, origRename, origSync })
	with := func(f failingTemp) func(string, string) (seqTemp, error) {
		return func(dir, pattern string) (seqTemp, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			f.File = file
			return f, nil
		}
	}
	cases := map[string]func(){
		"create": func() {
			seqCreateTemp = func(string, string) (seqTemp, error) { return nil, errSeqInjected }
		},
		"write":  func() { seqCreateTemp = with(failingTemp{write: errSeqInjected}) },
		"chmod":  func() { seqCreateTemp = with(failingTemp{chmod: errSeqInjected}) },
		"sync":   func() { seqCreateTemp = with(failingTemp{sync: errSeqInjected}) },
		"close":  func() { seqCreateTemp = with(failingTemp{close: errSeqInjected}) },
		"rename": func() { seqRename = func(string, string) error { return errSeqInjected } },
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			seqCreateTemp, seqRename, seqSyncDir = origCreate, origRename, origSync
			path := seqPath(t)
			if err := writeSeqFile(path, 7); err != nil {
				t.Fatal(err)
			}
			inject()
			if err := writeSeqFile(path, 8); !errors.Is(err, errSeqInjected) {
				t.Fatalf("write = %v", err)
			}
			if got := readMark(t, path); got != "7\n" {
				t.Fatalf("mark = %q after a failed write", got)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 1 {
				t.Fatalf("left behind %v", entries)
			}
		})
	}
	t.Run("directory sync", func(t *testing.T) {
		seqCreateTemp, seqRename = origCreate, origRename
		seqSyncDir = func(string) error { return errSeqInjected }
		if err := writeSeqFile(seqPath(t), 1); !errors.Is(err, errSeqInjected) {
			t.Fatalf("write = %v", err)
		}
	})
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	err := syncDir(filepath.Join(t.TempDir(), "absent"))
	if runtime.GOOS != "windows" && err == nil {
		t.Fatal("synced a directory that does not exist")
	}
}

func seqManager(t *testing.T, store *memSeq) (*Manager, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	m := &Manager{Log: slog.New(slog.NewTextHandler(&logs, nil)), SeqFile: seqPath(t)}
	if store != nil {
		m.SeqStore = store
	}
	return m, &logs
}

// The mark is the larger of the two copies, whichever holds it.
func TestAcceptSequenceTakesTheMax(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct{ file, store string }{
		"file ahead":  {"9", "4"},
		"store ahead": {"4", "9"},
	} {
		t.Run(name, func(t *testing.T) {
			st := &memSeq{val: []byte(c.store), found: true}
			m, _ := seqManager(t, st)
			if err := os.WriteFile(m.SeqFile, []byte(c.file), 0o600); err != nil {
				t.Fatal(err)
			}
			wantErr(t, m.acceptSequence(ctx, 8), "older than accepted 9")
			if err := m.acceptSequence(ctx, 9); err != nil {
				t.Fatal(err)
			}
			// Accepting the mark brings the copy that was behind up to it.
			if got := readMark(t, m.SeqFile); got != "9\n" && got != "9" {
				t.Fatalf("file = %q", got)
			}
			if string(st.val) != "9" {
				t.Fatalf("store = %q", st.val)
			}
		})
	}
}

// Every accept writes both copies; neither is ever lowered.
func TestAcceptSequenceNeverLowers(t *testing.T) {
	ctx := context.Background()
	st := &memSeq{}
	m, _ := seqManager(t, st)
	for _, seq := range []uint64{3, 5, 5} {
		if err := m.acceptSequence(ctx, seq); err != nil {
			t.Fatal(err)
		}
	}
	if got := readMark(t, m.SeqFile); got != "5\n" || string(st.val) != "5" {
		t.Fatalf("file %q store %q", got, st.val)
	}
	if len(st.putSeen) != 2 {
		t.Fatalf("store writes %q; an unchanged sequence must not rewrite", st.putSeen)
	}
	wantErr(t, m.acceptSequence(ctx, 4), "older than accepted 5")
	if got := readMark(t, m.SeqFile); got != "5\n" || string(st.val) != "5" {
		t.Fatalf("a refused manifest moved the mark: file %q store %q", got, st.val)
	}
}

// A clone sealed with the template's mark file and no store: the file alone
// refuses an older manifest, and the first accept seeds the new store.
func TestAcceptSequenceAfterASeal(t *testing.T) {
	ctx := context.Background()
	st := &memSeq{}
	m, _ := seqManager(t, st)
	if err := writeSeqFile(m.SeqFile, 20); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.acceptSequence(ctx, 19), "older than accepted 20")
	if err := m.acceptSequence(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if string(st.val) != "20" {
		t.Fatalf("store = %q", st.val)
	}
}

// A malformed file refuses every manifest and says so at ERROR; it is not
// rewritten, so the evidence stays for the operator.
func TestAcceptSequenceMalformedFileFailsClosed(t *testing.T) {
	st := &memSeq{val: []byte("2"), found: true}
	m, logs := seqManager(t, st)
	if err := os.WriteFile(m.SeqFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := m.acceptSequence(context.Background(), 1000)
	if !errors.Is(err, errSeqUnavailable) || !errors.Is(err, errSeqMalformed) {
		t.Fatalf("accept = %v", err)
	}
	if !strings.Contains(logs.String(), "level=ERROR") ||
		!strings.Contains(logs.String(), "mark file is unusable") {
		t.Fatalf("log: %s", logs.String())
	}
	if got := readMark(t, m.SeqFile); got != "garbage" || len(st.putSeen) != 0 {
		t.Fatalf("file %q, store writes %q", got, st.putSeen)
	}
}

func TestAcceptSequenceFileWriteFails(t *testing.T) {
	m, _ := seqManager(t, nil)
	m.SeqFile = filepath.Join(t.TempDir(), "absent", SequenceFile)
	if err := m.acceptSequence(context.Background(), 1); !errors.Is(err, errSeqPersist) {
		t.Fatalf("accept = %v", err)
	}
}

// The file alone (no store wired) is enough for the check.
func TestAcceptSequenceFileOnly(t *testing.T) {
	m, _ := seqManager(t, nil)
	if err := m.acceptSequence(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	wantErr(t, m.acceptSequence(context.Background(), 1), "older than accepted 2")
}
