package provision

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Linux guests normally get their anchor from cloud-init, so this is the cheap
// version: a filesystem udev has labelled WEAVEPROV and something has already
// mounted. Core does not mount it. Vars so tests can point them elsewhere.
var (
	byLabelDir    = "/dev/disk/by-label"
	mountInfoPath = "/proc/self/mountinfo"
)

func platformVolumes() ([]string, error) {
	dev, err := filepath.EvalSymlinks(filepath.Join(byLabelDir, VolumeLabel))
	if err != nil {
		// No such label: by far the usual case.
		return nil, nil //nolint:nilerr // absent is not an error
	}
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("reading mounts: %w", err)
	}
	defer f.Close()
	var roots []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m, ok := parseMountInfo(sc.Text())
		if !ok || m.source != dev || m.root != "/" {
			continue
		}
		if !m.readOnly {
			return nil, fmt.Errorf("%s at %s: %w", dev, m.point, errNotReadOnly)
		}
		roots = append(roots, m.point)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading mounts: %w", err)
	}
	return roots, nil
}

type mount struct {
	root, point, source string
	readOnly            bool
}

// parseMountInfo reads one line of /proc/self/mountinfo:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//
// root (4th) is the part of the filesystem mounted, point (5th) where, then the
// per-mount options; after the "-" separator, the type and the source.
func parseMountInfo(line string) (mount, bool) {
	fields := strings.Fields(line)
	sep := -1
	for i, f := range fields {
		if f == "-" {
			sep = i
			break
		}
	}
	if sep < 6 || sep+2 >= len(fields) {
		return mount{}, false
	}
	m := mount{
		root:   unescapeMount(fields[3]),
		point:  unescapeMount(fields[4]),
		source: unescapeMount(fields[sep+2]),
	}
	for _, o := range strings.Split(fields[5], ",") {
		if o == "ro" {
			m.readOnly = true
		}
	}
	return m, true
}

// unescapeMount undoes the kernel's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
