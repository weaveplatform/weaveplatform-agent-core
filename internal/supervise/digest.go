package supervise

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// FileDigest returns path's "sha256:<hex>", the form channel manifests use.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a module binary path core resolved itself
	if err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("digest of %s: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
