package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/certtrust"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/winsvc"
)

// memSCM is a minimal in-memory SCM: services start and stop instantly.
type memSCM struct {
	svcs    map[string]*memSvc
	openErr error
}

type memSvc struct {
	cfg   winsvc.Config
	state winsvc.State
	gone  bool
}

func (m *memSCM) Open(name string) (winsvc.Service, error) {
	if m.openErr != nil {
		return nil, m.openErr
	}
	s, ok := m.svcs[name]
	if !ok || s.gone {
		return nil, winsvc.ErrNotInstalled
	}
	return s, nil
}

func (m *memSCM) Create(c winsvc.Config) (winsvc.Service, error) {
	s := &memSvc{state: winsvc.Stopped}
	m.svcs[c.Name] = s
	return s, nil
}

func (m *memSCM) Close() error { return nil }

func (s *memSvc) Configure(c winsvc.Config) error { s.cfg = c; return nil }
func (s *memSvc) State() (winsvc.State, error)    { return s.state, nil }
func (s *memSvc) Start() error                    { s.state = winsvc.Running; return nil }
func (s *memSvc) Stop() error                     { s.state = winsvc.Stopped; return nil }
func (s *memSvc) Delete() error                   { s.gone = true; return nil }
func (s *memSvc) Close() error                    { return nil }

func exeName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

type svcEnv struct {
	scm        *memSCM
	src, dst   string
	keyDest    string
	restricted []string
	state      string
	trusted    []string
	untrusted  []string
}

func stubService(t *testing.T) *svcEnv {
	t.Helper()
	e := &svcEnv{scm: &memSCM{svcs: map[string]*memSvc{}}}
	e.src = t.TempDir()
	for _, n := range winsvc.Payload {
		if err := os.WriteFile(filepath.Join(e.src, exeName(n)), []byte(n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.dst = filepath.Join(t.TempDir(), "Weave")
	e.keyDest = filepath.Join(t.TempDir(), "weave", "channel.pub")
	e.state = filepath.Join(t.TempDir(), "ProgramData", "Weave")
	origM, origR, origE, origK, origW, origS := newManager, restrictDir, executable, channelKeyDest, serviceWaits, platformState
	origT, origU := trustCert, untrustCert
	t.Cleanup(func() {
		newManager, restrictDir, executable, channelKeyDest, serviceWaits, platformState = origM, origR, origE, origK, origW, origS
		trustCert, untrustCert = origT, origU
	})
	trustCert = func(c *certtrust.Certificate) error { e.trusted = append(e.trusted, c.Thumbprint); return nil }
	untrustCert = func(th string) error { e.untrusted = append(e.untrusted, th); return nil }
	platformState = func() string { return e.state }
	newManager = func() (winsvc.Manager, error) { return e.scm, nil }
	restrictDir = func(d string) error { e.restricted = append(e.restricted, d); return nil }
	executable = func() (string, error) { return filepath.Join(e.src, exeName("weaveboot")), nil }
	channelKeyDest = func() string { return e.keyDest }
	serviceWaits = winsvc.Waits{Poll: time.Millisecond, Timeout: time.Second}
	return e
}

func keyFile(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	p := filepath.Join(t.TempDir(), "channel.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func svc(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := entry(append([]string{"service"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// The unattended install: payload from beside weaveboot, the channel key,
// service environment, started — then the full verb set against it.
func TestServiceInstallAndVerbs(t *testing.T) {
	e := stubService(t)
	code, out, errOut := svc("install", "-install-dir", e.dst, "-channel-key", keyFile(t),
		"-env", "WEAVE_LOG_LEVEL=debug", "-env", "WEAVE_CHANNEL_PUB=C:\\k.pub", "-start")
	if code != 0 {
		t.Fatalf("install exit %d: %s%s", code, out, errOut)
	}
	s := e.scm.svcs[winsvc.DefaultName]
	if s.state != winsvc.Running || s.cfg.DisplayName != winsvc.DefaultDisplayName {
		t.Fatalf("service %+v", s)
	}
	if strings.Join(s.cfg.Env, ";") != `WEAVE_LOG_LEVEL=debug;WEAVE_CHANNEL_PUB=C:\k.pub` {
		t.Fatalf("env %q", s.cfg.Env)
	}
	if _, err := os.Stat(filepath.Join(e.dst, exeName("weave-agent"))); err != nil {
		t.Fatalf("payload not copied from beside weaveboot: %v", err)
	}
	if _, err := os.Stat(e.keyDest); err != nil {
		t.Fatalf("channel key not installed: %v", err)
	}
	if len(e.restricted) != 1 || e.restricted[0] != e.state {
		t.Fatalf("restricted %v, want the platform state root", e.restricted)
	}

	if code, out, _ := svc("status"); code != 0 || strings.TrimSpace(out) != "running" {
		t.Fatalf("status = %d %q", code, out)
	}
	if code, _, _ := svc("stop"); code != 0 {
		t.Fatalf("stop exit %d", code)
	}
	if code, out, _ := svc(
		"status",
	); code != exitNotRunning ||
		strings.TrimSpace(out) != "stopped" {
		t.Fatalf("status after stop = %d %q", code, out)
	}
	if code, _, _ := svc("start"); code != 0 {
		t.Fatalf("start exit %d", code)
	}
	if code, _, _ := svc("uninstall"); code != 0 {
		t.Fatalf("uninstall exit %d", code)
	}
	if code, out, _ := svc(
		"status",
	); code != exitNotRunning ||
		strings.TrimSpace(out) != "not-installed" {
		t.Fatalf("status after uninstall = %d %q", code, out)
	}
}

func TestServiceInstallFromSourceDirWithStateRedirect(t *testing.T) {
	e := stubService(t)
	executable = func() (string, error) { return "", errors.New("unused") }
	state := filepath.Join(t.TempDir(), "state")
	code, out, errOut := svc(
		"install",
		"-name",
		"WeaveAgentAlt",
		"-install-dir",
		e.dst,
		"-source-dir",
		e.src,
		"-env",
		"weave_state_dir="+state,
	)
	if code != 0 {
		t.Fatalf("install exit %d: %s%s", code, out, errOut)
	}
	if e.scm.svcs["WeaveAgentAlt"] == nil {
		t.Fatal("named service not created")
	}
	if len(e.restricted) != 1 || e.restricted[0] != state {
		t.Fatalf("restricted %v, want the redirected state root", e.restricted)
	}
}

func TestServiceInstallFailures(t *testing.T) {
	e := stubService(t)
	executable = func() (string, error) { return "", errors.New("no self") }
	if code, _, errOut := svc(
		"install",
		"-install-dir",
		e.dst,
	); code != 1 ||
		!strings.Contains(errOut, "no self") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	e = stubService(t)
	if code, _, errOut := svc(
		"install",
		"-install-dir",
		e.dst,
		"-env",
		"novalue",
	); code != 1 ||
		!strings.Contains(errOut, "KEY=VALUE") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestServiceUsageErrors(t *testing.T) {
	stubService(t)
	for _, args := range [][]string{
		{}, {"bogus"}, {"status", "extra"}, {"start", "-bogus"}, {"install", "-start=maybe"},
	} {
		if code, _, _ := svc(args...); code != 2 {
			t.Errorf("%q exit %d, want 2", args, code)
		}
	}
	if code, out, _ := svc(
		"help",
	); code != 0 ||
		!strings.Contains(out, "usage: weaveboot service") {
		t.Fatalf("help = %d %q", code, out)
	}
	if code, _, _ := svc("status", "-h"); code != 0 {
		t.Fatalf("status -h exit %d", code)
	}
}

func TestServiceManagerErrors(t *testing.T) {
	e := stubService(t)
	newManager = func() (winsvc.Manager, error) { return nil, winsvc.ErrUnsupported }
	if code, _, errOut := svc(
		"status",
	); code != 1 ||
		!strings.Contains(errOut, "only available on Windows") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	newManager = func() (winsvc.Manager, error) { return e.scm, nil }
	e.scm.openErr = errors.New("access denied")
	for _, verb := range []string{"status", "start", "stop", "uninstall"} {
		if code, _, errOut := svc(verb); code != 1 || !strings.Contains(errOut, "access denied") {
			t.Fatalf("%s exit %d: %s", verb, code, errOut)
		}
	}
}

// Off Windows the real manager refuses cleanly rather than pretending.
func TestServiceUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the real SCM is exercised in internal/winsvc")
	}
	if code, _, errOut := svc(
		"status",
	); code != 1 ||
		!strings.Contains(errOut, "only available on Windows") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestPlatformStateDefault(t *testing.T) {
	if platformState() == "" {
		t.Fatal("no platform state root")
	}
}

// --trust-cert trusts the certificate before the service starts, and
// uninstall --untrust --remove-files takes the trust and the files away.
func TestServiceTrustAndFullUninstall(t *testing.T) {
	e := stubService(t)
	const thumb = "A6A3936288B9409ED7A3458CF81014A77AB59B51"
	code, out, errOut := svc("install", "-install-dir", e.dst,
		"-trust-cert", "../../packaging/windows/weave-codesign.crt", "-start")
	if code != 0 || strings.Join(e.trusted, ",") != thumb {
		t.Fatalf("install exit %d, trusted %v: %s%s", code, e.trusted, out, errOut)
	}
	code, out, errOut = svc("uninstall", "-install-dir", e.dst, "-untrust", "-remove-files")
	if code != 0 || strings.Join(e.untrusted, ",") != thumb {
		t.Fatalf("uninstall exit %d, untrusted %v: %s%s", code, e.untrusted, out, errOut)
	}
	if _, err := os.Stat(e.dst); !os.IsNotExist(err) {
		t.Fatalf("install dir left: %v", err)
	}
	if code, _, errOut := svc(
		"install",
		"-install-dir",
		e.dst,
		"-trust-cert",
		"missing.crt",
	); code != 1 ||
		!strings.Contains(errOut, "code-signing certificate") {
		t.Fatalf("missing certificate: exit %d: %s", code, errOut)
	}
}
