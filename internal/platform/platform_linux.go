package platform

import (
	"bufio"
	"os"
	"strings"
)

// osReleasePath is a variable so tests can feed fill a file with fields the
// test host's own os-release lacks (BUILD_ID is absent on most distros).
var osReleasePath = "/etc/os-release"

func fill(info *Info) {
	if hn, err := os.Hostname(); err == nil {
		info.Hostname = hn
	}
	f, err := os.Open(osReleasePath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "VERSION_ID="); ok {
			info.Version = strings.Trim(v, `"`)
		}
		if v, ok := strings.CutPrefix(line, "BUILD_ID="); ok {
			info.Build = strings.Trim(v, `"`)
		}
	}
}

// Paths returns the platform filesystem contract on Linux.
func Paths() PathSet {
	return PathSet{
		StateDir:   "/var/lib/weave",
		LogDir:     "/var/log/weave",
		RunDir:     "/run/weave",
		StagingDir: "/var/lib/weave/staging",
	}
}
