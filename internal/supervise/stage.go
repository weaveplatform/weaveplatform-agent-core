package supervise

import (
	"fmt"
	"io"
	"os"
	"time"
)

// copyExecutable copies a module binary to a staging path that must not
// exist yet, read-only and executable.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // a module binary path core resolved itself
	if err != nil {
		return fmt.Errorf("opening module binary: %w", err)
	}
	defer in.Close()
	//nolint:gosec // dst is under core's ExecDir
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555)
	if err != nil {
		return fmt.Errorf("creating staged binary: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copying module binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing staged binary: %w", err)
	}
	return nil
}

// stagedRemoveTries and stagedRemoveWait bound removeStaged. Windows can
// hold an image file for a moment after its process has exited.
var (
	stagedRemoveTries = 40
	stagedRemoveWait  = 50 * time.Millisecond
)

// removeStaged removes a stopped module's staged copies, retrying while the
// OS lets go of the image. Best effort: what it cannot remove, the next
// launch or SweepOrphans does.
func removeStaged(dir string) error {
	var err error
	for range stagedRemoveTries {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		time.Sleep(stagedRemoveWait)
	}
	return fmt.Errorf("removing staged binary: %w", err)
}
