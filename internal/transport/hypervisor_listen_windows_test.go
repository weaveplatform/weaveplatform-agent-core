package transport

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	ws "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/winsock"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// The Winsock GUID and the registry subkey name must be the same identity the
// host dials; a mismatch fails with nothing but a refused bind.
func TestHvServiceGUIDMatchesTheRegistryName(t *testing.T) {
	if got, want := hvServiceGUID(2010).String(), vsockServiceID(2010); got != want {
		t.Fatalf("GUID %s, registry name %s", got, want)
	}
}

type fakeServices struct {
	present bool
	err     error
	key     string
	name    string
}

func (f *fakeServices) registered(string) bool { return f.present }

func (f *fakeServices) register(key, name string) error {
	f.key, f.name = key, name
	return f.err
}

func TestEnsureGuestService(t *testing.T) {
	want := guestServicesKey + `\000007da-facb-11e6-bd58-64006a7986d3`

	present := &fakeServices{present: true}
	ensureGuestService(quietLog(), present, 2010)
	if present.key != "" {
		t.Fatal("re-registered a service that already exists")
	}

	missing := &fakeServices{}
	ensureGuestService(quietLog(), missing, 2010)
	if missing.key != want || !strings.Contains(missing.name, "2010") {
		t.Fatalf("registered %q (%q), want %q", missing.key, missing.name, want)
	}

	logs := &logBuffer{}
	ensureGuestService(
		slog.New(slog.NewTextHandler(logs, nil)),
		&fakeServices{err: errors.New("access denied")},
		2010,
	)
	if !strings.Contains(logs.String(), "cannot register") ||
		!strings.Contains(logs.String(), "SYSTEM") {
		t.Fatalf("a failed registration must say why the listen will fail: %s", logs.String())
	}
}

// The real registry code, under HKCU so the test neither needs elevation nor
// touches the machine's guest services.
func TestRegServicesUnderHKCU(t *testing.T) {
	base := fmt.Sprintf(`Software\WeaveAgentTest\%d`, time.Now().UnixNano())
	t.Cleanup(func() { registry.RegDeleteTree(registry.HKEY_CURRENT_USER, &base) })
	r := regServices{root: registry.HKEY_CURRENT_USER}
	key := base + `\` + vsockServiceID(2010)
	if r.registered(key) {
		t.Fatal("fresh key reported registered")
	}
	if err := r.register(key, "test service"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !r.registered(key) {
		t.Fatal("registered key not found")
	}
	// Idempotent: an existing registration is refreshed, not an error.
	if err := r.register(key, "test service"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if err := (regServices{root: registry.HKEY(0)}).register(key, "x"); err == nil {
		t.Fatal("register under an invalid root succeeded")
	}
}

func TestRegSZ(t *testing.T) {
	if got := regSZ("Aé"); string(got) != "A\x00\xe9\x00\x00\x00" {
		t.Fatalf("regSZ = %q", got)
	}
}

func TestListenSocketWindows(t *testing.T) {
	oldReg, oldListen := guestServices, hvListen
	t.Cleanup(func() { guestServices, hvListen = oldReg, oldListen })
	reg := &fakeServices{}
	guestServices = reg
	var bound win32.GUID
	hvListen = func(g win32.GUID) (connListener, error) { bound = g; return newPipeListener(), nil }

	if _, err := listenSocket(
		map[string]string{"kind": "hvsocket", "port": "2010"},
		quietLog(),
	); err != nil {
		t.Fatalf("listenSocket: %v", err)
	}
	if bound != hvServiceGUID(2010) || reg.key == "" {
		t.Fatalf("bound %s, registered %q", bound, reg.key)
	}
	for _, attrs := range []map[string]string{
		{"kind": "vsock", "port": "2010"},
		{"kind": "hvsocket", "port": ""},
	} {
		if _, err := listenSocket(attrs, quietLog()); !errors.Is(err, errChannelAttrs) {
			t.Errorf("listenSocket(%v) = %v", attrs, err)
		}
	}
}

// The real AF_HYPERV listen. A CI runner may or may not be a Hyper-V guest and
// the service is not registered, so either outcome is acceptable; what must
// hold is that a failure is reported, not a hang, and that a listener that did
// come up can be closed.
func TestListenHvSocketReal(t *testing.T) {
	l, err := listenHvSocket(hvServiceGUID(52012))
	if err != nil {
		if !strings.Contains(err.Error(), "hvsocket") {
			t.Fatalf("error does not say what failed: %v", err)
		}
		t.Logf("AF_HYPERV listen unavailable here (expected off a Hyper-V guest): %v", err)
		return
	}
	l.Close() //nolint:errcheck
}

// sockaddrIn4 is SOCKADDR_IN. The Winsock plumbing is family-independent, so
// it is exercised over loopback TCP on any Windows host.
type sockaddrIn4 struct {
	Family uint16
	Port   [2]byte // network order
	Addr   [4]byte
	Zero   [8]byte
}

func loopbackListener(t *testing.T) (*wsListener, string) {
	t.Helper()
	sa := sockaddrIn4{Family: uint16(ws.AF_INET), Addr: [4]byte{127, 0, 0, 1}}
	l, err := winsockListen(
		int32(ws.AF_INET),
		int32(ws.IPPROTO_TCP),
		unsafe.Pointer(&sa),
		int32(unsafe.Sizeof(sa)),
	)
	if err != nil {
		t.Fatalf("winsockListen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	var bound sockaddrIn4
	n := int32(unsafe.Sizeof(bound))
	if rc, err := ws.Getsockname(l.s, (*ws.SOCKADDR)(unsafe.Pointer(&bound)), &n); rc != 0 {
		t.Fatalf("getsockname: %v", err)
	}
	return l, fmt.Sprintf("127.0.0.1:%d", int(bound.Port[0])<<8|int(bound.Port[1]))
}

func TestWinsockStream(t *testing.T) {
	l, addr := loopbackListener(t)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("client read %q, %v", buf, err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("conn read %q, %v", buf, err)
	}
	client.Close()
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read after the peer closed = %v, want EOF", err)
	}
	conn.Close()
	conn.Close() // idempotent
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("write on a closed socket succeeded")
	}
	if _, err := conn.Read(buf); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("read on a closed socket = %v, want a socket error", err)
	}
}

// Close is how the accept loop stops; it must unblock a pending Accept.
func TestWinsockCloseUnblocksAccept(t *testing.T) {
	l, _ := loopbackListener(t)
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	time.Sleep(20 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
}

func TestWinsockListenFailures(t *testing.T) {
	if _, err := winsockListen(9999, 0, nil, 0); err == nil {
		t.Fatal("socket() of a nonsense family succeeded")
	}
	// Binding a port already listened on is refused.
	_, addr := loopbackListener(t)
	var port int
	fmt.Sscanf(addr[strings.LastIndex(addr, ":")+1:], "%d", &port)
	sa := sockaddrIn4{
		Family: uint16(ws.AF_INET),
		Port:   [2]byte{byte(port >> 8), byte(port)},
		Addr:   [4]byte{127, 0, 0, 1},
	}
	if l, err := winsockListen(
		int32(ws.AF_INET),
		int32(ws.IPPROTO_TCP),
		unsafe.Pointer(&sa),
		int32(unsafe.Sizeof(sa)),
	); err == nil {
		l.Close()
		t.Fatal("bound a port already in use")
	} else if !strings.Contains(
		err.Error(),
		"bind",
	) {
		t.Fatalf("bind failure not named: %v", err)
	}
	if err := wsErr(nil); !errors.Is(err, errWinsock) {
		t.Fatalf("wsErr(nil) = %v", err)
	}
}
