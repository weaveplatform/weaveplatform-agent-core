package platform

// PathSet is the filesystem contract core and modules agree on without core
// exporting it over the wire. All paths are the system (privileged) set;
// per-user session processes derive their own under the user profile.
type PathSet struct {
	// StateDir holds durable state: the store, installed module versions,
	// cached manifests.
	StateDir string
	// LogDir holds rotating log files.
	LogDir string
	// RunDir holds sockets and pidfiles; cleared on boot.
	RunDir string
	// StagingDir holds fetched-but-not-promoted artifacts.
	StagingDir string
}
