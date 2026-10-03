// Package buildinfo carries version metadata injected with -ldflags -X
// (see LDFLAGS in the Makefile). Release builds set all three; a plain
// `go build` reports "devel" and empty values.
package buildinfo

var (
	version   = "devel"
	commit    = ""
	buildDate = ""
)

// Version returns the release version or "devel".
func Version() string { return version }

// Commit returns the source commit, if known.
func Commit() string { return commit }

// BuildDate returns the RFC 3339 build time, if known.
func BuildDate() string { return buildDate }
