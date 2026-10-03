package platform

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

func fill(info *Info) {
	if hn, err := os.Hostname(); err == nil {
		info.Hostname = hn
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	// CurrentMajorVersionNumber exists on Win10+; DisplayVersion on 20H2+.
	if major, _, err := k.GetIntegerValue("CurrentMajorVersionNumber"); err == nil {
		if minor, _, err := k.GetIntegerValue("CurrentMinorVersionNumber"); err == nil {
			if build, _, err := k.GetStringValue("CurrentBuildNumber"); err == nil {
				info.Version = itoa(major) + "." + itoa(minor) + "." + build
				info.Build = build
			}
		}
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// Paths returns the platform filesystem contract on Windows.
func Paths() PathSet {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	root := filepath.Join(programData, "Weave")
	return PathSet{
		StateDir:   root,
		LogDir:     filepath.Join(root, "logs"),
		RunDir:     filepath.Join(root, "run"),
		StagingDir: filepath.Join(root, "staging"),
	}
}
