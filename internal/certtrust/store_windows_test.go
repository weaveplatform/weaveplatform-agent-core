package certtrust

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// elevated skips a test that writes LocalMachine stores when this process
// cannot. CI's Windows runner is elevated, so there it always runs.
func elevated(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Skipf("not elevated: %v", err)
	}
}

// The whole round trip against the real LocalMachine stores, the ones the
// installer uses: trusted in both, idempotent, and gone again after.
func TestTrustRoundTripLocalMachine(t *testing.T) {
	c, err := Parse(mint(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Untrust(LocalMachine, c.Thumbprint) })
	err = Trust(LocalMachine, c)
	elevated(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if err := Trust(LocalMachine, c); err != nil {
		t.Fatalf("re-trusting: %v", err)
	}
	got, err := Trusted(LocalMachine, c.Thumbprint)
	if err != nil || !got["Root"] || !got["TrustedPublisher"] {
		t.Fatalf("after Trust: %v, %v", got, err)
	}
	if err := Untrust(LocalMachine, strings.ToLower(c.Thumbprint)); err != nil {
		t.Fatal(err)
	}
	got, err = Trusted(LocalMachine, c.Thumbprint)
	if err != nil || got["Root"] || got["TrustedPublisher"] {
		t.Fatalf("after Untrust: %v, %v", got, err)
	}
	if err := Untrust(LocalMachine, c.Thumbprint); err != nil {
		t.Fatalf("untrusting what is not there: %v", err)
	}
}

// CurrentUser, through TrustedPublisher only: adding to CurrentUser\Root
// raises a modal confirmation dialog by design, which would hang a test.
func TestTrustCurrentUserPublisher(t *testing.T) {
	old := Stores
	Stores = []string{"TrustedPublisher"}
	t.Cleanup(func() { Stores = old })
	c, err := Parse(mint(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Untrust(CurrentUser, c.Thumbprint) })
	if err := Trust(CurrentUser, c); err != nil {
		t.Fatal(err)
	}
	if got, err := Trusted(CurrentUser, c.Thumbprint); err != nil || !got["TrustedPublisher"] {
		t.Fatalf("Trusted = %v, %v", got, err)
	}
	if err := Untrust(CurrentUser, c.Thumbprint); err != nil {
		t.Fatal(err)
	}
}

func TestStoreErrors(t *testing.T) {
	if _, err := Trusted(CurrentUser, "nope"); !errors.Is(err, errBadThumbprint) {
		t.Fatalf("bad thumbprint: %v", err)
	}
	if err := Untrust(CurrentUser, "nope"); !errors.Is(err, errBadThumbprint) {
		t.Fatalf("bad thumbprint: %v", err)
	}
	old := Stores
	t.Cleanup(func() { Stores = old })
	Stores = []string{`No\Such\Store`}
	if err := Trust(CurrentUser, &Certificate{DER: []byte{1}}); err == nil {
		t.Fatal("opened a store that does not exist")
	}
	// An existing store, but bytes that are not a certificate.
	Stores = []string{"TrustedPublisher"}
	if err := Trust(CurrentUser, &Certificate{DER: []byte{1, 2, 3}, Thumbprint: "x"}); err == nil {
		t.Fatal("added a certificate that is not one")
	}
}
