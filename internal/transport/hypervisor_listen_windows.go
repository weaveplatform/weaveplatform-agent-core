package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	ws "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/winsock"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// guestServicesKey is where Windows looks up which HvSocket services a guest
// may listen on. A Linux guest binds any vsock port it likes; a Windows guest
// may only bind a service GUID registered here, and an unregistered bind fails
// with a bare Winsock error that says nothing about the cause.
const guestServicesKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`

// serviceRegistry is the GuestCommunicationServices store, behind a seam so the
// registration logic is testable without writing HKLM.
type serviceRegistry interface {
	registered(key string) bool
	register(key, elementName string) error
}

// Seams for tests; nothing but a test writes them.
var (
	guestServices serviceRegistry = regServices{root: registry.HKEY_LOCAL_MACHINE}
	hvListen                      = listenHvSocket
)

// listenSocket listens for the host on the HvSocket service for the probed
// vsock port, from any partition (the guest has exactly one parent).
func listenSocket(attrs map[string]string, log *slog.Logger) (connListener, error) {
	if attrs["kind"] != "hvsocket" {
		return nil, fmt.Errorf("%w: kind %q on windows", errChannelAttrs, attrs["kind"])
	}
	port, err := channelPort(attrs)
	if err != nil {
		return nil, err
	}
	ensureGuestService(log, guestServices, port)
	return hvListen(hvServiceGUID(port))
}

// ensureGuestService registers the channel's service if it is not already.
//
// Core does this itself rather than leaving it to an installer because the
// registration is a precondition of the listen, not of the install: an image
// built without it would otherwise come up with a channel that can never be
// bound. Writing HKLM needs an elevated core — the service runs as
// LocalSystem — so a failure is logged and the listen attempted anyway; it
// will fail, and the log line above it says why.
func ensureGuestService(log *slog.Logger, reg serviceRegistry, port uint32) {
	key := guestServicesKey + `\` + vsockServiceID(port)
	if reg.registered(key) {
		return
	}
	if err := reg.register(
		key,
		fmt.Sprintf("Weave agent hypervisor channel (vsock port %d)", port),
	); err != nil {
		log.Error("hypervisor channel: cannot register the HvSocket guest service; "+
			"the listen will be refused until it exists (core must run as SYSTEM, or the image must create the key)",
			"key", `HKLM\`+key, "err", err)
		return
	}
	log.Info("hypervisor channel: registered the HvSocket guest service", "key", `HKLM\`+key)
}

// regServices is serviceRegistry over the real registry. root is a field so a
// test can exercise it under HKCU instead of HKLM.
type regServices struct{ root registry.HKEY }

// The 64-bit view explicitly: Hyper-V reads the native hive, and a 32-bit
// build would otherwise be redirected under WOW6432Node, register there, and
// still see its bind refused.
const regView = registry.KEY_WOW64_64KEY

func (r regServices) registered(key string) bool {
	var h registry.HKEY
	if registry.RegOpenKeyEx(
		r.root,
		&key,
		0,
		registry.KEY_QUERY_VALUE|regView,
		&h,
	) != foundation.ERROR_SUCCESS {
		return false
	}
	registry.RegCloseKey(h)
	return true
}

func (r regServices) register(key, elementName string) error {
	var h registry.HKEY
	if rc := registry.RegCreateKeyEx(r.root, key, nil, registry.REG_OPTION_NON_VOLATILE,
		registry.KEY_SET_VALUE|regView, nil, &h, nil); rc != foundation.ERROR_SUCCESS {
		return fmt.Errorf("create key: %w", syscall.Errno(rc))
	}
	defer registry.RegCloseKey(h)
	name := "ElementName"
	if rc := registry.RegSetValueEx(
		h,
		&name,
		registry.REG_SZ,
		regSZ(elementName),
	); rc != foundation.ERROR_SUCCESS {
		return fmt.Errorf("set ElementName: %w", syscall.Errno(rc))
	}
	return nil
}

// regSZ encodes s as REG_SZ data: little-endian UTF-16 with its terminator.
func regSZ(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// hvServiceGUID is vsockServiceID as the GUID Winsock binds.
func hvServiceGUID(port uint32) win32.GUID {
	return win32.GUID{
		Data1: port, Data2: 0xfacb, Data3: 0x11e6,
		Data4: [8]byte{0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3},
	}
}

const hvProtocolRaw = 1 // HV_PROTOCOL_RAW

// sockaddrHV mirrors SOCKADDR_HV, which no binding exposes: family, reserved,
// VM id, service id. A zero VM id is HV_GUID_WILDCARD.
type sockaddrHV struct {
	Family    uint16
	Reserved  uint16
	VMID      win32.GUID
	ServiceID win32.GUID
}

func listenHvSocket(service win32.GUID) (connListener, error) {
	sa := sockaddrHV{Family: ws.AF_HYPERV, ServiceID: service}
	return winsockListen(
		int32(ws.AF_HYPERV),
		hvProtocolRaw,
		unsafe.Pointer(&sa),
		int32(unsafe.Sizeof(sa)),
	)
}

var wsStartup sync.Once

// winsockListen is the family-independent part of the listen, so tests can
// drive it over AF_INET on a machine that is not a Hyper-V guest.
//
// Results are judged by return value, never by the error alone: these
// bindings report GetLastError, which a successful call is free to leave
// stale.
func winsockListen(af, proto int32, sa unsafe.Pointer, salen int32) (*wsListener, error) {
	// No WSACleanup: Winsock reference-counts startups per process and
	// unwinding would break other users' sockets. Process exit reclaims it.
	// A failed startup fails socket() below, which reports it.
	wsStartup.Do(func() {
		var d ws.WSADATA
		_, _ = ws.WSAStartup(0x0202, &d)
	})
	s, err := ws.Socket(af, ws.SOCK_STREAM, proto)
	if s == ws.INVALID_SOCKET {
		return nil, fmt.Errorf("hvsocket socket: %w", wsErr(err))
	}
	if rc, err := ws.Bind(s, (*ws.SOCKADDR)(sa), salen); rc != 0 {
		_, _ = ws.Closesocket(s)
		return nil, fmt.Errorf("hvsocket bind (is the service registered?): %w", wsErr(err))
	}
	if rc, err := ws.Listen(s, 8); rc != 0 {
		_, _ = ws.Closesocket(s)
		return nil, fmt.Errorf("hvsocket listen: %w", wsErr(err))
	}
	return &wsListener{s: s}, nil
}

func wsErr(err error) error {
	if err == nil {
		return errWinsock
	}
	return err
}

var errWinsock = fmt.Errorf("winsock call failed with no error code")

type wsListener struct {
	s    ws.SOCKET
	once sync.Once
}

// Accept blocks with no deadline; Close is what unblocks it (closesocket fails
// the pending accept).
func (l *wsListener) Accept() (io.ReadWriteCloser, error) {
	ns, err := ws.Accept(l.s, nil, nil)
	if ns == ws.INVALID_SOCKET {
		return nil, fmt.Errorf("hvsocket accept: %w", wsErr(err))
	}
	return &wsConn{s: ns}, nil
}

func (l *wsListener) Close() error {
	l.once.Do(func() { _, _ = ws.Closesocket(l.s) })
	return nil
}

// wsConn is a connected Winsock stream. Blocking, no deadlines: Close from
// another goroutine is what ends a pending Read, which is how a replaced
// connection's read loop is stopped.
type wsConn struct {
	s    ws.SOCKET
	once sync.Once
}

// Read reports recv's 0 as io.EOF (graceful close), and an empty p as (0, nil)
// without calling recv, whose 0 would otherwise read as EOF.
func (c *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := ws.Recv(
		c.s,
		foundation.PSTR(&p[0]),
		int32(min(len(p), math.MaxInt32)),
		0,
	)
	switch {
	case n == 0:
		return 0, io.EOF
	case n < 0:
		return 0, fmt.Errorf("hvsocket recv: %w", wsErr(err))
	}
	return int(n), nil
}

// Write loops: send may take fewer bytes than offered, and io.Writer forbids a
// short count without an error.
func (c *wsConn) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := ws.Send(
			c.s,
			foundation.PSTR(&p[total]),
			int32(min(len(p)-total, math.MaxInt32)),
			0,
		)
		if n <= 0 {
			return total, fmt.Errorf("hvsocket send: %w", wsErr(err))
		}
		total += int(n)
	}
	return total, nil
}

// Close is idempotent: Winsock reuses handle values, so a second closesocket
// could close whichever socket has since taken the number — and the replacing
// accept loop and the read loop both close a replaced connection.
func (c *wsConn) Close() error {
	c.once.Do(func() { _, _ = ws.Closesocket(c.s) })
	return nil
}
