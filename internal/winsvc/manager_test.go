package winsvc

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var fastWaits = Waits{Poll: time.Millisecond, Timeout: time.Second}

func testConfig() Config {
	return Config{
		Name:        "WeaveAgent",
		DisplayName: DefaultDisplayName,
		BinaryPath:  `C:\w\weaveboot.exe`,
		Env:         []string{"A=1"},
	}
}

func TestInstallCreatesThenUpdatesInPlace(t *testing.T) {
	m := newFake()
	created, err := Install(m, testConfig())
	if err != nil || !created {
		t.Fatalf("first install: created=%v err=%v", created, err)
	}
	c := testConfig()
	c.Env = []string{"B=2"}
	created, err = Install(m, c)
	if err != nil || created {
		t.Fatalf("re-install: created=%v err=%v", created, err)
	}
	s := m.services["WeaveAgent"]
	if s.configs != 2 || s.cfg.Env[0] != "B=2" {
		t.Fatalf("re-install did not converge config: %+v", s)
	}
	if strings.Count(strings.Join(m.log, ","), "create") != 1 {
		t.Fatalf("service created twice: %v", m.log)
	}
}

func TestInstallErrors(t *testing.T) {
	if _, err := Install(newFake(), Config{}); err == nil {
		t.Fatal("invalid config accepted")
	}
	m := newFake()
	m.openErr = errBoom
	if _, err := Install(m, testConfig()); !errors.Is(err, errBoom) {
		t.Fatalf("open error = %v", err)
	}
	m = newFake()
	m.createErr = errBoom
	if _, err := Install(m, testConfig()); !errors.Is(err, errBoom) {
		t.Fatalf("create error = %v", err)
	}
	m = newFake()
	m.services["WeaveAgent"] = &fakeService{m: m, state: Stopped, configureErr: errBoom}
	if _, err := Install(m, testConfig()); !errors.Is(err, errBoom) {
		t.Fatalf("configure error = %v", err)
	}
}

func TestStartStopQuery(t *testing.T) {
	m := newFake()
	if _, err := Install(m, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := Start(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	if st, err := Query(m, "WeaveAgent"); err != nil || st != Running {
		t.Fatalf("after start: %v %v", st, err)
	}
	// Starting a running service succeeds.
	if err := Start(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	if err := Stop(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	// Stopping a stopped service succeeds without a stop control.
	before := len(m.log)
	if err := Stop(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	if len(m.log) != before {
		t.Fatalf("stopped service was sent a stop: %v", m.log[before:])
	}
	if _, err := Query(m, "nope"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("query missing = %v", err)
	}
}

func TestStopWaitsOutStopPending(t *testing.T) {
	m := newFake()
	m.services["s"] = &fakeService{m: m, state: StopPending}
	if err := Stop(m, "s", fastWaits); err != nil {
		t.Fatal(err)
	}
	for _, l := range m.log {
		if l == "stop" {
			t.Fatal("a stop-pending service was sent another stop")
		}
	}
}

func TestStartFailures(t *testing.T) {
	if err := Start(newFake(), "missing", fastWaits); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing = %v", err)
	}
	m := newFake()
	m.services["s"] = &fakeService{m: m, state: Stopped, startErr: errBoom}
	if err := Start(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("start error = %v", err)
	}
	m.services["s"] = &fakeService{m: m, state: Stopped, startFails: true}
	if err := Start(m, "s", fastWaits); !errors.Is(err, ErrStartFailed) {
		t.Fatalf("failed start = %v", err)
	}
	m.services["s"] = &fakeService{m: m, state: Stopped, stuck: true}
	if err := Start(
		m,
		"s",
		Waits{Poll: time.Millisecond, Timeout: 20 * time.Millisecond},
	); !errors.Is(err, ErrTimeout) ||
		!strings.Contains(err.Error(), "still start-pending") {
		t.Fatalf("hung start = %v", err)
	}
	m.services["s"] = &fakeService{m: m, state: Stopped, stateErr: errBoom}
	if err := Start(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("query error = %v", err)
	}
}

func TestStopFailures(t *testing.T) {
	if err := Stop(newFake(), "missing", fastWaits); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing = %v", err)
	}
	m := newFake()
	m.services["s"] = &fakeService{m: m, state: Running, stateErr: errBoom}
	if err := Stop(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("query error = %v", err)
	}
	m.services["s"] = &fakeService{m: m, state: Running, stopErr: errBoom}
	if err := Stop(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("stop error = %v", err)
	}
	// The service stopped between the query and the control.
	m.services["s"] = &fakeService{m: m, state: Running, stopErr: ErrNotActive}
	m.services["s"].stuck = true
	if err := Stop(
		m,
		"s",
		Waits{Poll: time.Millisecond, Timeout: 10 * time.Millisecond},
	); !errors.Is(
		err,
		ErrTimeout,
	) {
		t.Fatal("a service that never reaches stopped must time out")
	}
}

func TestUninstall(t *testing.T) {
	if err := Uninstall(newFake(), "missing", fastWaits); err != nil {
		t.Fatalf("uninstalling a missing service = %v", err)
	}
	m := newFake()
	if _, err := Install(m, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := Start(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(m, "WeaveAgent", fastWaits); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(m.log, ",")
	if !strings.HasSuffix(got, "stop,delete") {
		t.Fatalf("uninstall must stop before delete: %s", got)
	}
	if _, err := Query(m, "WeaveAgent"); !errors.Is(err, ErrNotInstalled) {
		t.Fatal("service still present")
	}

	m = newFake()
	m.openErr = errBoom
	if err := Uninstall(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("open error = %v", err)
	}
	m = newFake()
	m.services["s"] = &fakeService{m: m, state: Running, stopErr: errBoom}
	if err := Uninstall(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("stop error = %v", err)
	}
	m.services["s"] = &fakeService{m: m, state: Stopped, deleteErr: errBoom}
	if err := Uninstall(m, "s", fastWaits); !errors.Is(err, errBoom) {
		t.Fatalf("delete error = %v", err)
	}
}
