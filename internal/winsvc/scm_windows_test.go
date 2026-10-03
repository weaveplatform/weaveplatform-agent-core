package winsvc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	reg "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// childDirEnv is set only in the service's Environment value, so its
// presence means this test binary was started by the SCM as the service
// under test.
const childDirEnv = "WEAVE_WINSVC_CHILD_DIR"

// TestServiceChild is the body of the real service in
// TestRealServiceLifecycle. Run by go test directly, it skips.
func TestServiceChild(t *testing.T) {
	dir := os.Getenv(childDirEnv)
	if dir == "" {
		t.Skip("only runs as the service started by TestRealServiceLifecycle")
	}
	isSvc, detErr := IsService()
	err := Run(func(ctx context.Context) error {
		os.WriteFile(
			filepath.Join(dir, "started"), //nolint:errcheck
			[]byte(
				fmt.Sprintf(
					"service=%v err=%v extra=%s",
					isSvc,
					detErr,
					os.Getenv("WEAVE_WINSVC_EXTRA"),
				),
			),
			0o644,
		)
		<-ctx.Done()
		return os.WriteFile(filepath.Join(dir, "stopped"), []byte("graceful"), 0o644)
	})
	if err != nil {
		os.WriteFile(filepath.Join(dir, "run-error"), []byte(err.Error()), 0o644) //nolint:errcheck
	}
}

// TestRealServiceLifecycle installs a uniquely named service that runs this
// test binary (as TestServiceChild), checks the registration the SCM
// recorded, re-installs it in place, starts it, stops it gracefully and
// removes it. It needs an elevated token, which the Windows CI runner has.
func TestRealServiceLifecycle(t *testing.T) {
	if os.Getenv(childDirEnv) != "" {
		t.Skip("inside the service")
	}
	m, err := NewManager()
	if err != nil {
		t.Skipf("needs an elevated connection to the SCM: %v", err)
	}
	// A cleanup, not a defer: the uninstall cleanup below needs the handle,
	// and deferred calls run before any cleanup. Cleanups run last-in first
	// out, so this closes after the uninstall.
	t.Cleanup(func() { m.Close() }) //nolint:errcheck

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := fmt.Sprintf("WeaveAgentTest%d", time.Now().UnixNano())
	waits := Waits{Poll: 100 * time.Millisecond, Timeout: 60 * time.Second}
	t.Cleanup(func() {
		if err := Uninstall(m, name, waits); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	cfg := Config{
		Name:        name,
		DisplayName: "Weave winsvc test",
		Description: "Temporary service created by winsvc tests.",
		BinaryPath:  self,
		Args:        []string{"-test.run=^TestServiceChild$", "-test.count=1"},
		Env:         []string{childDirEnv + "=" + dir},
	}
	created, err := Install(m, cfg)
	if err != nil || !created {
		t.Fatalf("install: created=%v err=%v", created, err)
	}
	checkRegistration(t, cfg)

	cfg.Env = append(cfg.Env, "WEAVE_WINSVC_EXTRA=second")
	if created, err = Install(m, cfg); err != nil || created {
		t.Fatalf("re-install: created=%v err=%v", created, err)
	}
	checkRegistration(t, cfg)

	if err := Start(m, name, waits); err != nil {
		t.Fatalf("start: %v (run-error: %s)", err, readFile(dir, "run-error"))
	}
	if !waitFile(filepath.Join(dir, "started"), 30*time.Second) {
		t.Fatal("service body never ran")
	}
	if got, want := readFile(dir, "started"), "service=true err=<nil> extra=second"; got != want {
		t.Fatalf("service saw %q, want %q", got, want)
	}
	if st, err := Query(m, name); err != nil || st != Running {
		t.Fatalf("query: %v %v", st, err)
	}
	if err := Stop(m, name, waits); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if readFile(dir, "stopped") != "graceful" {
		t.Fatal("stop did not reach the service body through its context")
	}
	if err := Uninstall(m, name, waits); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := Query(m, name)
		if errors.Is(err, ErrNotInstalled) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("service still present after uninstall: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := Uninstall(m, name, waits); err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
}

func TestRealManagerErrors(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Skipf("needs an elevated connection to the SCM: %v", err)
	}
	defer m.Close() //nolint:errcheck
	if _, err := m.Open("WeaveAgentDoesNotExist"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("open missing = %v", err)
	}
	if err := setEnvironment("WeaveAgentDoesNotExist", nil); err == nil {
		t.Fatal("environment written for a missing service")
	}
	if _, err := m.Create(Config{Name: "WeaveAgent\\Bad", BinaryPath: `C:\x.exe`}); err == nil {
		t.Fatal("invalid service name accepted by the SCM")
	}
}

// checkRegistration reads back what the SCM stored under the service key —
// the same place sc.exe, services.msc and the SCM itself read it from.
func checkRegistration(t *testing.T, c Config) {
	t.Helper()
	if got := regString(t, c.Name, "ImagePath"); got != c.CommandLine() {
		t.Errorf("ImagePath = %s, want %s", got, c.CommandLine())
	}
	if got := regString(t, c.Name, "ObjectName"); !strings.EqualFold(got, "LocalSystem") {
		t.Errorf("ObjectName = %s", got)
	}
	if got := regDWORD(t, c.Name, "Start"); got != 2 {
		t.Errorf("Start = %d, want 2 (automatic)", got)
	}
	if got := regDWORD(t, c.Name, "FailureActionsOnNonCrashFailures"); got != 1 {
		t.Errorf("FailureActionsOnNonCrashFailures = %d", got)
	}
	if got := regDWORD(
		t,
		c.Name,
		"PreshutdownTimeout",
	); got != uint32(
		PreshutdownTimeout/time.Millisecond,
	) {
		t.Errorf("PreshutdownTimeout = %d", got)
	}
	if got := DecodeMultiSZ(regValue(t, c.Name, "Environment")); !reflect.DeepEqual(got, c.Env) {
		t.Errorf("Environment = %q, want %q", got, c.Env)
	}
	// SERVICE_FAILURE_ACTIONS as stored: reset period, two reserved
	// pointers' worth, count, then {type, delay} pairs.
	fa := regValue(t, c.Name, "FailureActions")
	if len(fa) < 20+3*8 {
		t.Fatalf("FailureActions too short: % x", fa)
	}
	if n := binary.LittleEndian.Uint32(fa[12:]); n != 3 {
		t.Errorf("FailureActions count = %d", n)
	}
	for i := 0; i < 3; i++ {
		typ := binary.LittleEndian.Uint32(fa[20+8*i:])
		delay := binary.LittleEndian.Uint32(fa[24+8*i:])
		if typ != 1 || delay != uint32(RestartDelay/time.Millisecond) {
			t.Errorf("action %d = type %d delay %d", i, typ, delay)
		}
	}
}

func regValue(t *testing.T, service, value string) []byte {
	t.Helper()
	var k reg.HKEY
	sub := serviceKey(service)
	if rc := reg.RegOpenKeyEx(
		reg.HKEY_LOCAL_MACHINE,
		&sub,
		0,
		reg.KEY_QUERY_VALUE|reg.KEY_WOW64_64KEY,
		&k,
	); rc != 0 {
		t.Fatalf("open %s: %d", sub, rc)
	}
	defer reg.RegCloseKey(k)
	var typ reg.REG_VALUE_TYPE
	var size uint32
	if rc := reg.RegQueryValueEx(k, &value, &typ, nil, &size); rc != 0 {
		t.Fatalf("query %s size: %d", value, rc)
	}
	buf := make([]byte, size)
	if size == 0 {
		return buf
	}
	if rc := reg.RegQueryValueEx(k, &value, &typ, &buf[0], &size); rc != 0 {
		t.Fatalf("query %s: %d", value, rc)
	}
	return buf[:size]
}

func regString(t *testing.T, service, value string) string {
	t.Helper()
	if s := DecodeMultiSZ(regValue(t, service, value)); len(s) > 0 {
		return s[0]
	}
	return ""
}

func regDWORD(t *testing.T, service, value string) uint32 {
	t.Helper()
	b := regValue(t, service, value)
	if len(b) != 4 {
		t.Fatalf("%s is %d bytes, want a DWORD", value, len(b))
	}
	return binary.LittleEndian.Uint32(b)
}

func readFile(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return string(b)
}

func waitFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
