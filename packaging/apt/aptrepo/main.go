// Command aptrepo turns a directory of .deb files into a signed flat apt
// repository.
//
// Why this exists rather than dpkg-scanpackages and apt-ftparchive: those tools
// are Debian-only, and the machines that build and test this package are macOS
// hosts running Linux guests. A Go tool builds the repository from the same
// laptop that builds the .deb, with no Homebrew dpkg and no container round-trip.
// Only the signature needs an external program, because only gpg holds the key.
//
// What apt actually verifies is this: it fetches InRelease (or Release +
// Release.gpg), checks the signature against the key named in the sources.list
// `signed-by=`, then checks Packages against the digests inside that signed
// Release, then checks each .deb against the digest inside Packages. So the
// signature over Release is what makes every byte downstream of it trusted — an
// unsigned repository of individually signed .debs would not give apt anything it
// checks by default.
//
//	aptrepo -in dist -out /tmp/weave-apt -key ABCD1234
//	aptrepo -verify /tmp/weave-apt
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"  //nolint:gosec // apt's Release format carries an MD5Sum section; not a security claim
	"crypto/sha1" //nolint:gosec // ditto for SHA1; SHA256 below is the one that matters
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// gpgCommand is a seam: tests substitute a fake gpg so signing and
// verification run without a keyring.
var gpgCommand = func(args ...string) *exec.Cmd { return exec.Command("gpg", args...) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aptrepo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "dist", "directory to read .deb files from")
	out := fs.String("out", "", "directory to write the repository into (required unless -verify)")
	key := fs.String(
		"key",
		"",
		"gpg key id or uid to sign Release with; empty leaves the repo unsigned",
	)
	origin := fs.String("origin", "weave", "Origin/Label field for Release")
	verify := fs.String(
		"verify",
		"",
		"verify an existing repository directory instead of building one",
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *verify != "" {
		if err := verifyRepo(*verify, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, "aptrepo:", err)
			return 1
		}
		return 0
	}
	if *out == "" {
		fmt.Fprintln(stderr, "aptrepo: -out is required")
		return 2
	}
	if err := build(*in, *out, *key, *origin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "aptrepo:", err)
		return 1
	}
	return 0
}

func build(in, out, key, origin string, stdout, stderr io.Writer) error {
	debs, err := filepath.Glob(filepath.Join(in, "*.deb"))
	if err != nil {
		return err
	}
	if len(debs) == 0 {
		return fmt.Errorf("no .deb files in %s", in)
	}
	sort.Strings(debs)

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	var packages bytes.Buffer
	for _, deb := range debs {
		stanza, err := packageStanza(deb)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(deb), err)
		}
		if err := copyFile(deb, filepath.Join(out, filepath.Base(deb))); err != nil {
			return err
		}
		packages.WriteString(stanza)
		packages.WriteString("\n")
		fmt.Fprintln(stdout, "added", filepath.Base(deb))
	}

	if err := os.WriteFile(filepath.Join(out, "Packages"), packages.Bytes(), 0o644); err != nil {
		return err
	}
	if err := writeGzip(filepath.Join(out, "Packages.gz"), packages.Bytes()); err != nil {
		return err
	}

	release, err := releaseFile(out, origin)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "Release"), []byte(release), 0o644); err != nil {
		return err
	}

	if key == "" {
		fmt.Fprintln(stdout, "wrote unsigned repository to", out)
		fmt.Fprintln(
			stdout,
			"apt will refuse this repository unless the source is marked [trusted=yes] — "+
				"pass -key to sign it, which is what the trust actually rests on",
		)
		return nil
	}
	if err := sign(out, key, stderr); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "wrote signed repository to", out)
	return nil
}

// packageStanza builds one Packages entry: the .deb's own control fields, plus
// the fields only the repository can supply — where the file is and what it
// hashes to. apt checks the downloaded .deb against these, so they are the link
// between the signed Release and the bytes that get installed.
func packageStanza(path string) (string, error) {
	control, err := readControl(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	sums, err := digests(path)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(control, "\n"))
	b.WriteString("\n")
	// "./" — a flat repository serves packages from the same directory as the
	// index, and apt resolves Filename relative to the source URI.
	fmt.Fprintf(&b, "Filename: ./%s\n", filepath.Base(path))
	fmt.Fprintf(&b, "Size: %d\n", info.Size())
	fmt.Fprintf(&b, "MD5sum: %s\n", sums["md5"])
	fmt.Fprintf(&b, "SHA1: %s\n", sums["sha1"])
	fmt.Fprintf(&b, "SHA256: %s\n", sums["sha256"])
	return b.String(), nil
}

// releaseFile indexes the index files. Everything apt trusts hangs off the
// digests listed here, because this is the only file that gets signed.
func releaseFile(dir, origin string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Origin: %s\n", origin)
	fmt.Fprintf(&b, "Label: %s\n", origin)
	b.WriteString("Suite: stable\n")
	b.WriteString("Codename: stable\n")
	// RFC 1123 in UTC, which is the only form apt parses reliably.
	fmt.Fprintf(&b, "Date: %s\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"))
	b.WriteString("Acquire-By-Hash: no\n")

	indexes := []string{"Packages", "Packages.gz"}
	for _, algo := range []struct{ field, digest string }{
		{"MD5Sum", "md5"}, {"SHA1", "sha1"}, {"SHA256", "sha256"},
	} {
		fmt.Fprintf(&b, "%s:\n", algo.field)
		for _, name := range indexes {
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil {
				return "", err
			}
			sums, err := digests(path)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, " %s %d %s\n", sums[algo.digest], info.Size(), name)
		}
	}
	return b.String(), nil
}

// sign writes both signature forms. InRelease (inline) is what modern apt
// prefers; Release.gpg (detached) is the fallback an older client asks for, and
// costs one extra call to produce.
func sign(dir, key string, stderr io.Writer) error {
	release := filepath.Join(dir, "Release")
	for _, args := range [][]string{
		{"--batch", "--yes", "--local-user", key, "--clearsign", "--output", filepath.Join(dir, "InRelease"), release},
		{"--batch", "--yes", "--local-user", key, "--detach-sign", "--armor", "--output", filepath.Join(dir, "Release.gpg"), release},
		{"--batch", "--yes", "--armor", "--export", "--output", filepath.Join(dir, "weave-archive-keyring.asc"), key},
	} {
		cmd := gpgCommand(args...)
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("gpg %s: %w", args[len(args)-2], err)
		}
	}
	return nil
}

// verifyRepo re-checks a built repository the way apt will: signature over
// Release, Release's digests over the indexes, Packages' digests over the .debs.
// A repository that passes here and fails in a guest is a transport or key-trust
// problem, not a content one — which is worth being able to tell apart, because
// apt reports both as "not signed with a key in the trusted set".
func verifyRepo(dir string, stdout, stderr io.Writer) error {
	if _, err := os.Stat(filepath.Join(dir, "InRelease")); err == nil {
		cmd := gpgCommand("--verify", filepath.Join(dir, "InRelease"))
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("InRelease signature: %w", err)
		}
		fmt.Fprintln(stdout, "InRelease signature ok")
	} else {
		fmt.Fprintln(stdout, "no InRelease — repository is unsigned")
	}

	release, err := os.ReadFile(filepath.Join(dir, "Release"))
	if err != nil {
		return err
	}
	checked := 0
	for line := range strings.SplitSeq(string(release), "\n") {
		if !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || len(fields[0]) != 64 { // SHA256 lines only
			continue
		}
		sums, err := digests(filepath.Join(dir, fields[2]))
		if err != nil {
			return err
		}
		if sums["sha256"] != fields[0] {
			return fmt.Errorf("%s: SHA256 in Release does not match the file", fields[2])
		}
		checked++
	}
	if checked == 0 {
		return errors.New("Release lists no SHA256 digests")
	}
	fmt.Fprintf(stdout, "%d index digests ok\n", checked)

	packages, err := os.ReadFile(filepath.Join(dir, "Packages"))
	if err != nil {
		return err
	}
	pkgs := 0
	for stanza := range strings.SplitSeq(string(packages), "\n\n") {
		var name, want string
		for line := range strings.SplitSeq(stanza, "\n") {
			switch {
			case strings.HasPrefix(line, "Filename: "):
				name = strings.TrimPrefix(line, "Filename: ")
			case strings.HasPrefix(line, "SHA256: "):
				want = strings.TrimPrefix(line, "SHA256: ")
			}
		}
		if name == "" || want == "" {
			continue
		}
		sums, err := digests(filepath.Join(dir, filepath.Base(name)))
		if err != nil {
			return err
		}
		if sums["sha256"] != want {
			return fmt.Errorf("%s: SHA256 in Packages does not match the file", name)
		}
		pkgs++
	}
	if pkgs == 0 {
		return errors.New("Packages lists no packages")
	}
	fmt.Fprintf(stdout, "%d package digests ok\n", pkgs)
	return nil
}

// readControl pulls the control file out of a .deb.
//
// A .deb is an ar archive of three members in order: debian-binary,
// control.tar.*, data.tar.*. Only the middle one is needed here, and only its
// ./control member.
func readControl(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	magic := make([]byte, 8)
	if _, err := io.ReadFull(f, magic); err != nil {
		return "", err
	}
	if string(magic) != "!<arch>\n" {
		return "", errors.New("not an ar archive")
	}

	for {
		// ar header: 16 name, 12 mtime, 6 uid, 6 gid, 8 mode, 10 size, 2 magic.
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(f, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("no control member in .deb")
			}
			return "", err
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil {
			return "", fmt.Errorf("bad ar member size: %w", err)
		}
		if strings.HasPrefix(name, "control.tar") {
			member := io.LimitReader(f, size)
			return controlFromTar(name, member)
		}
		// Members are padded to an even offset.
		if _, err := io.CopyN(io.Discard, f, size+size%2); err != nil {
			return "", err
		}
	}
}

func controlFromTar(name string, r io.Reader) (string, error) {
	switch filepath.Ext(name) {
	case ".gz":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return "", err
		}
		defer zr.Close()
		return controlFromPlainTar(zr)
	case ".tar", "":
		return controlFromPlainTar(r)
	default:
		// Deliberately not pulling in xz/zstd decoders for this: the packages
		// this reads are built by the configs next door, which use gzip. A
		// clear refusal beats a silent dependency on a compressor the reader
		// has to keep matching.
		return "", fmt.Errorf("control member %s uses an unsupported compression; "+
			"build the package with gzip control compression", name)
	}
}

func controlFromPlainTar(r io.Reader) (string, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", errors.New("no ./control in control archive")
		}
		if err != nil {
			return "", err
		}
		if strings.TrimPrefix(hdr.Name, "./") != "control" {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
}

func digests(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hashes := map[string]hash.Hash{
		"md5":    md5.New(),  //nolint:gosec // apt Release MD5Sum section, as above
		"sha1":   sha1.New(), //nolint:gosec // apt Release SHA1 section, as above
		"sha256": sha256.New(),
	}
	writers := make([]io.Writer, 0, len(hashes))
	for _, h := range hashes {
		writers = append(writers, h)
	}
	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(hashes))
	for name, h := range hashes {
		out[name] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}

func copyFile(src, dst string) error {
	if src == dst {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func writeGzip(path string, data []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
