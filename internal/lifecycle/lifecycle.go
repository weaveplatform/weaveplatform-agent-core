// Package lifecycle owns module install: fetch, verify, stage alongside,
// health-gated promote, N-1 retention, rollback. The rules are spec §8's:
// verify before exec, stage then promote, swap atomically, fail closed.
//
// On disk each installed module is versioned:
//
//	modules/<id>/current            version string
//	modules/<id>/previous           version string (N-1 retention)
//	modules/<id>/versions/<ver>/    binary, module.manifest.json, config.json
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/agent/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/layout"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/manifestverify"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/supervise"
)

// Install and rollback refusals. Each is wrapped with the detail of the
// case, so callers can tell them apart with errors.Is.
var (
	errNoChannelSource = errors.New("lifecycle: channel installs unavailable")
	errNotInChannel    = errors.New("not in channel")
	errVersionMismatch = errors.New("requested version not in channel")
	errNoArtifact      = errors.New("lifecycle: no artifact for")
	errNoPrevious      = errors.New("lifecycle: no previous version retained for")
	errVanished        = errors.New("module vanished from supervisor")
	errModuleState     = errors.New("module state")
	errGateTimeout     = errors.New("health gate timed out waiting for healthy")
	errFetchStatus     = errors.New("unexpected HTTP status")
	errExpired         = errors.New("lifecycle: channel manifest expired")
	errSequence        = errors.New("lifecycle: channel manifest rollback refused")
	errArtifactFetch   = errors.New("artifact fetch")
	errArtifactSize    = errors.New("lifecycle: artifact size")
	errArtifactDigest  = errors.New("lifecycle: artifact digest")
	errNoBinary        = errors.New("lifecycle: no binary for")
)

// SeqStore is the subset of the store the manager needs to persist the
// channel-manifest anti-rollback high-water mark.
type SeqStore interface {
	Get(ctx context.Context, namespace, key string) ([]byte, bool, error)
	Put(ctx context.Context, namespace, key string, value []byte) error
}

// Manager performs installs and rollbacks against the supervisor.
type Manager struct {
	Log        *slog.Logger
	Layout     layout.Layout
	Verifier   supervise.Verifier
	Supervisor *supervise.Supervisor
	// RootPub verifies channel manifests; nil disables channel installs
	// (local installs still work in dev builds).
	RootPub ed25519.PublicKey
	// ManifestURL is where the signed channel manifest bundle lives:
	// <base>/manifest.json{,.sig} and <base>/signing.pub{,.sig}.
	ManifestURL string
	// Client for fetches; nil gets a 5-minute-timeout default.
	Client *http.Client
	// GateTimeout bounds the post-promote health gate; zero gets 30s.
	GateTimeout time.Duration
	// GateStable is how long the module must stay running to pass the
	// gate; zero gets 3s.
	GateStable time.Duration
	// SeqStore and SeqFile persist the channel-manifest anti-rollback
	// high-water mark (seqmark.go); with neither set there is no sequence
	// check (local/dev installs). A SeqStore that fails refuses manifests,
	// which is how a core running without its store keeps refusing them.
	SeqStore SeqStore
	SeqFile  string

	// installMu serializes install/rollback per module id, so two
	// concurrent control-socket operations can't interleave Rename/current
	// writes and Supervisor.Replace calls.
	installMu   sync.Mutex
	perModuleMu map[string]*sync.Mutex
}

// lockModule returns the per-module install lock, creating it on first use.
func (m *Manager) lockModule(id string) *sync.Mutex {
	m.installMu.Lock()
	defer m.installMu.Unlock()
	if m.perModuleMu == nil {
		m.perModuleMu = make(map[string]*sync.Mutex)
	}
	mu, ok := m.perModuleMu[id]
	if !ok {
		mu = &sync.Mutex{}
		m.perModuleMu[id] = mu
	}
	return mu
}

// LockModule takes the per-module lock install and rollback hold, and returns
// its release. Core's module reload holds it while it compares a module on
// disk with the running one and acts on the difference: a promote replaces
// the process before it flips `current`, and a reload that looked in between
// would see the two disagree and put the old version back.
func (m *Manager) LockModule(id string) (unlock func()) {
	mu := m.lockModule(id)
	mu.Lock()
	return mu.Unlock
}

func (m *Manager) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// InstallLocal installs a module from a local directory containing the
// binary and its module.manifest.json (dev builds' path — the verifier
// still runs).
func (m *Manager) InstallLocal(ctx context.Context, dir string) (string, error) {
	mf, err := manifest.Load(filepath.Join(dir, "module.manifest.json"))
	if err != nil {
		return "", fmt.Errorf("lifecycle: %w", err)
	}
	mu := m.lockModule(mf.ID)
	mu.Lock()
	defer mu.Unlock()
	bin, err := findBinary(dir, mf.ID)
	if err != nil {
		return "", err
	}
	stage, err := m.stageFiles(mf, bin, filepath.Join(dir, "config.json"))
	if err != nil {
		return "", err
	}
	if err := m.promote(ctx, mf, stage); err != nil {
		return "", err
	}
	return mf.Version, nil
}

// Install fetches and installs a module per the signed channel manifest.
// version empty means the channel's current.
func (m *Manager) Install(ctx context.Context, moduleID, version string) (string, error) {
	if m.RootPub == nil || m.ManifestURL == "" {
		return "", fmt.Errorf("%w: no manifest source configured", errNoChannelSource)
	}
	ch, err := m.fetchChannel(ctx)
	if err != nil {
		return "", err
	}
	cm, ok := ch.Module(moduleID)
	if !ok {
		return "", fmt.Errorf("lifecycle: module %q %w %q", moduleID, errNotInChannel, ch.Channel)
	}
	mu := m.lockModule(moduleID)
	mu.Lock()
	defer mu.Unlock()
	if version != "" && cm.Version != version {
		return "", fmt.Errorf("lifecycle: %w: channel %q carries %s@%s, not %s",
			errVersionMismatch, ch.Channel, moduleID, cm.Version, version)
	}
	art, ok := manifest.ArtifactForHost(cm.Artifacts)
	if !ok {
		return "", fmt.Errorf("%w %s/%s", errNoArtifact, runtime.GOOS, runtime.GOARCH)
	}

	// Fetch to a temp file and check the digest before anything else
	// touches it.
	tmp, err := m.download(ctx, art.URL, art.Digest, art.Size)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	mf := cm.ModuleManifest([]manifest.Platform{{OS: runtime.GOOS, Arch: runtime.GOARCH}})
	// Validate before the manifest's id/version reach any filesystem path.
	if err := mf.Validate(); err != nil {
		return "", fmt.Errorf("lifecycle: channel manifest for %s: %w", moduleID, err)
	}
	stage, err := m.stageFiles(mf, tmp, "")
	if err != nil {
		return "", err
	}
	if err := m.promote(ctx, mf, stage); err != nil {
		return "", err
	}
	return mf.Version, nil
}

// Rollback flips a module to its retained previous version.
func (m *Manager) Rollback(ctx context.Context, moduleID string) (string, error) {
	mu := m.lockModule(moduleID)
	mu.Lock()
	defer mu.Unlock()
	moduleDir := filepath.Join(m.Layout.ModulesDir, moduleID)
	prev, err := os.ReadFile(filepath.Join(moduleDir, "previous"))
	if err != nil {
		return "", fmt.Errorf("%w %s: %w", errNoPrevious, moduleID, err)
	}
	prevVersion := strings.TrimSpace(string(prev))
	verDir := filepath.Join(moduleDir, "versions", prevVersion)
	mf, err := manifest.Load(filepath.Join(verDir, "module.manifest.json"))
	if err != nil {
		return "", fmt.Errorf("lifecycle: %w", err)
	}
	current, _ := os.ReadFile(filepath.Join(moduleDir, "current"))

	if err := m.activate(ctx, mf, verDir); err != nil {
		return "", err
	}
	// The rolled-back-from version becomes "previous" so an operator can
	// flip forward again.
	// Best effort: the rollback itself has already succeeded.
	_ = writeFileString(filepath.Join(moduleDir, "previous"), strings.TrimSpace(string(current)))
	return prevVersion, nil
}

// stageFiles copies the binary (and optional config) into the staging
// area and verifies the signature there — before anything reaches the
// install tree.
func (m *Manager) stageFiles(mf *manifest.Manifest, binPath, configPath string) (string, error) {
	stage := filepath.Join(m.Layout.StagingDir, mf.ID, mf.Version)
	if err := os.RemoveAll(stage); err != nil {
		return "", fmt.Errorf("lifecycle: clearing stage: %w", err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return "", fmt.Errorf("lifecycle: creating stage: %w", err)
	}
	stagedBin := filepath.Join(stage, binaryName(mf.ID))
	if err := copyFile(binPath, stagedBin, 0o700); err != nil {
		return "", err
	}
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			if err := copyFile(configPath, filepath.Join(stage, "config.json"), 0o600); err != nil {
				return "", err
			}
		}
	}
	mfBytes, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return "", fmt.Errorf("lifecycle: encoding manifest: %w", err)
	}
	stagedManifest := filepath.Join(stage, "module.manifest.json")
	if err := os.WriteFile(stagedManifest, mfBytes, 0o600); err != nil {
		return "", fmt.Errorf("lifecycle: staging manifest: %w", err)
	}
	// Verify before anything can exec it. Non-negotiable.
	if err := m.Verifier.Verify(stagedBin, mf); err != nil {
		os.RemoveAll(stage)
		return "", fmt.Errorf("lifecycle: staged binary failed verification: %w", err)
	}
	return stage, nil
}

// promote moves the staged version into the install tree, flips current,
// swaps the running process, and health-gates the result; on failure it
// restores the old version and reports the error.
func (m *Manager) promote(ctx context.Context, mf *manifest.Manifest, stage string) error {
	moduleDir := filepath.Join(m.Layout.ModulesDir, mf.ID)
	verDir := filepath.Join(moduleDir, "versions", mf.Version)
	if err := os.MkdirAll(filepath.Dir(verDir), 0o700); err != nil {
		return fmt.Errorf("lifecycle: creating versions dir: %w", err)
	}
	if err := os.RemoveAll(verDir); err != nil {
		return fmt.Errorf("lifecycle: clearing version dir: %w", err)
	}
	if err := os.Rename(stage, verDir); err != nil {
		return fmt.Errorf("lifecycle: promoting stage: %w", err)
	}

	oldVersion := ""
	if b, err := os.ReadFile(filepath.Join(moduleDir, "current")); err == nil {
		oldVersion = strings.TrimSpace(string(b))
	}

	if err := m.activate(ctx, mf, verDir); err != nil {
		// Roll back to the old version if there was one.
		if oldVersion != "" && oldVersion != mf.Version {
			oldDir := filepath.Join(moduleDir, "versions", oldVersion)
			if oldMf, lerr := manifest.Load(
				filepath.Join(oldDir, "module.manifest.json"),
			); lerr == nil {
				if rerr := m.activate(ctx, oldMf, oldDir); rerr != nil {
					m.Log.Error(
						"rollback after failed promote also failed",
						"module",
						mf.ID,
						"err",
						rerr,
					)
				} else {
					m.Log.Warn("promote failed; rolled back", "module", mf.ID, "to", oldVersion)
				}
			}
		}
		return fmt.Errorf(
			"lifecycle: promote of %s@%s failed health gate: %w",
			mf.ID,
			mf.Version,
			err,
		)
	}

	// Success: retain exactly N-1.
	if oldVersion != "" && oldVersion != mf.Version {
		// Best effort: the promote has succeeded; a lost marker only costs
		// the rollback target.
		_ = writeFileString(filepath.Join(moduleDir, "previous"), oldVersion)
		m.prune(moduleDir, mf.Version, oldVersion)
	}
	m.Log.Info("module promoted", "module", mf.ID, "version", mf.Version)
	return nil
}

// activate swaps the running process to verDir's version and health-gates
// it. `current` is flipped only after the gate passes — a promote that
// fails its gate must not leave a broken version recorded as current, and
// (with no rollback target) the broken runner is stopped so a reboot does
// not relaunch it. The caller bounds the gate via ctx; the runner itself
// lives on the supervisor's run-lifetime context.
func (m *Manager) activate(ctx context.Context, mf *manifest.Manifest, verDir string) error {
	bin, err := findBinary(verDir, mf.ID)
	if err != nil {
		return err
	}
	var config []byte
	// verDir is core's install tree for a validated manifest id and version.
	cfgPath := filepath.Join(verDir, "config.json")
	if b, err := os.ReadFile(cfgPath); err == nil { //nolint:gosec // see above
		config = b
	}
	// Replace takes no context: the runner lives on the supervisor's
	// run-lifetime context, not on this install's.
	spec := supervise.Spec{Manifest: mf, BinPath: bin, Config: config}
	if err := m.Supervisor.Replace(spec); err != nil { //nolint:contextcheck // see above
		return fmt.Errorf("lifecycle: %w", err)
	}
	if err := m.healthGate(ctx, mf.ID); err != nil {
		m.Supervisor.StopModule(mf.ID)
		return err
	}
	moduleDir := filepath.Join(m.Layout.ModulesDir, mf.ID)
	return writeFileString(filepath.Join(moduleDir, "current"), mf.Version)
}

// healthGate waits for the module to be running and stay running.
func (m *Manager) healthGate(ctx context.Context, id string) error {
	timeout := m.GateTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	stable := m.GateStable
	if stable == 0 {
		stable = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var healthySince time.Time
	for time.Now().Before(deadline) {
		st, ok := m.statusOf(id)
		if !ok {
			return errVanished
		}
		switch st.State {
		case supervise.StateRunning:
			// Gate on health, not mere liveness: a running-but-unhealthy
			// module must not be promoted. The stable timer advances only
			// while the module reports HEALTHY; DEGRADED, UNHEALTHY, or a
			// not-yet-polled (nil) health resets it, so a module that
			// cannot reach healthy within the window fails the gate.
			if st.Health.GetStatus() == agentv1.Health_STATUS_HEALTHY {
				if healthySince.IsZero() {
					healthySince = time.Now()
				} else if time.Since(healthySince) >= stable {
					return nil
				}
			} else {
				healthySince = time.Time{}
			}
		case supervise.StateWaitingForSession:
			// A per-user module with nobody at the console has nothing to
			// prove yet: its binary is verified, and the gate cannot wait for
			// a login that may be days away — holding the install for one
			// would fail every install on an unattended host. Its first
			// session start is still supervised (backoff, start limit); a
			// broken version shows as start-limited there, not here.
			m.Log.Info("module promoted without a health proof: waiting for a console session",
				"module", id)
			return nil
		case supervise.StateStartLimited,
			supervise.StateUnsupportedProtocol,
			supervise.StateRequirementsUnmet:
			return fmt.Errorf("%w %s: %s", errModuleState, st.State, st.Detail)
		default:
			healthySince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("lifecycle: health gate: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errGateTimeout
}

func (m *Manager) statusOf(id string) (supervise.Status, bool) {
	return m.Supervisor.Modules().Get(id)
}

// prune deletes every version except keep and prev.
func (m *Manager) prune(moduleDir, keep, prev string) {
	entries, err := os.ReadDir(filepath.Join(moduleDir, "versions"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != keep && e.Name() != prev {
			os.RemoveAll(filepath.Join(moduleDir, "versions", e.Name()))
		}
	}
}

// fetchChannel downloads and verifies the signed channel manifest bundle.
func (m *Manager) fetchChannel(ctx context.Context) (*manifest.ChannelManifest, error) {
	get := func(name string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(m.ManifestURL, "/")+"/"+name, nil)
		if err != nil {
			return nil, fmt.Errorf("lifecycle: %s: %w", name, err)
		}
		resp, err := m.client().Do(req)
		if err != nil {
			return nil, fmt.Errorf("lifecycle: %s: %w", name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s: %w", name, resp.Status, errFetchStatus)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("lifecycle: reading %s: %w", name, err)
		}
		return body, nil
	}
	var b manifestverify.Bundle
	var err error
	if b.Manifest, err = get("manifest.json"); err != nil {
		return nil, err
	}
	if b.ManifestSig, err = get("manifest.json.sig"); err != nil {
		return nil, err
	}
	if b.SigningKey, err = get("signing.pub"); err != nil {
		return nil, err
	}
	if b.SigningKeySig, err = get("signing.pub.sig"); err != nil {
		return nil, err
	}
	ch, err := manifestverify.Verify(m.RootPub, b)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: %w", err)
	}
	// Freshness + anti-rollback, checked only after the signature is
	// valid: a genuine signature gives integrity, not recency. Reject an
	// expired (stale) manifest and any whose sequence is below the
	// highest we've accepted (a replayed older-but-signed document).
	if ch.Expired(time.Now()) {
		return nil, fmt.Errorf("%w at %s", errExpired, ch.Expires)
	}
	if m.SeqStore != nil || m.SeqFile != "" {
		if err := m.acceptSequence(ctx, ch.Sequence); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

// manifestSeqNamespace is the core-owned store namespace for the channel
// manifest anti-rollback high-water mark.
const manifestSeqNamespace = "core.manifest"

// download fetches url to a temp file, enforcing digest and size.
func (m *Manager) download(ctx context.Context, url, digest string, size int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("lifecycle: %w: %w", errArtifactFetch, err)
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("lifecycle: %w: %w", errArtifactFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("lifecycle: %w: %s", errArtifactFetch, resp.Status)
	}
	tmp, err := os.CreateTemp(m.Layout.StagingDir, "dl-*")
	if err != nil {
		return "", fmt.Errorf("lifecycle: download temp file: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, size+1))
	tmp.Close()
	if err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("lifecycle: %w: %w", errArtifactFetch, err)
	}
	if n != size {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("%w %d, manifest says %d", errArtifactSize, n, size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("%w %s, manifest says %s", errArtifactDigest, got, digest)
	}
	return tmp.Name(), nil
}

func binaryName(id string) string {
	if runtime.GOOS == "windows" {
		return id + ".exe"
	}
	return id
}

func findBinary(dir, id string) (string, error) {
	for _, cand := range []string{binaryName(id), "module", "module.exe"} {
		p := filepath.Join(dir, cand)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() { //nolint:gosec // dir is core-chosen
			return p, nil
		}
	}
	return "", fmt.Errorf("%w %s in %s", errNoBinary, id, dir)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("lifecycle: copying %s: %w", src, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	return nil
}

// writeFileString writes atomically: a crash mid-write must not leave a
// truncated `current`/`previous` marker that resolves to garbage on the
// next boot. Write to a temp file in the same directory, then rename.
//
// path is always a marker inside core's own install tree, built from a
// validated module id; the gosec taint findings below are about that path.
func writeFileString(path, s string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // core-internal path
		return fmt.Errorf("lifecycle: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(s + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: writing %s: %w", path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:gosec // from os.CreateTemp
		return fmt.Errorf("lifecycle: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil { //nolint:gosec // core-internal path
		return fmt.Errorf("lifecycle: %w", err)
	}
	return nil
}
