// Package version carries core's build identity, stamped at link time:
//
//	go build -ldflags "-X .../internal/version.Version=1.2.3"
package version

// Version is core's semver. "dev" when unstamped.
var Version = "dev"
