package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/hostserv"
)

var errInjected = errors.New("injected")

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// A fresh device gets a persistent id derived from its own key, and both the
// key and the id survive a restart.
func TestFreshIdentityAndKeyPersistence(t *testing.T) {
	store := hostserv.NewMemStore()
	p := &Provider{Log: testLog(), Store: store}
	if err := p.Init(); err != nil {
		t.Fatal(err)
	}
	id, eph, tenant := p.WhoAmI(context.Background())
	if eph || !strings.HasPrefix(id, "device-") || len(id) != len("device-")+32 || tenant != "" ||
		!p.Enrolled() {
		t.Fatalf("fresh identity: %s eph=%v tenant=%q enrolled=%v", id, eph, tenant, p.Enrolled())
	}
	if id != deriveDeviceID(p.priv) {
		t.Fatalf("id %s is not derived from the key", id)
	}

	p2 := &Provider{Log: testLog(), Store: store}
	if err := p2.Init(); err != nil {
		t.Fatal(err)
	}
	if !p.priv.Equal(p2.priv) {
		t.Fatal("keypair not persisted across restart")
	}
	if id2, _, _ := p2.WhoAmI(context.Background()); id2 != id {
		t.Fatalf("device id changed across restart: %s -> %s", id, id2)
	}
}

// A keypair saved by a core that predates derived ids gets its id from that
// same key, and keeps it.
func TestKeyWithoutIDGetsADerivedID(t *testing.T) {
	store := hostserv.NewMemStore()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(identityState{PrivateKey: base64.StdEncoding.EncodeToString(priv)})
	store.Put(context.Background(), storeNamespace, "state", raw) //nolint:errcheck
	p := &Provider{Log: testLog(), Store: store}
	if err := p.Init(); err != nil {
		t.Fatal(err)
	}
	if id, eph, _ := p.WhoAmI(context.Background()); id != deriveDeviceID(priv) || eph {
		t.Fatalf("id = %s eph=%v, want derived from the stored key", id, eph)
	}
	saved, _, _ := store.Get(context.Background(), storeNamespace, "state")
	var st identityState
	if err := json.Unmarshal(saved, &st); err != nil || st.DeviceID != deriveDeviceID(priv) {
		t.Fatalf("derived id not persisted: %s %v", saved, err)
	}
	// Saving it can fail; startup reports that rather than run on an id it
	// could not keep.
	fs := &failingStore{MemStore: hostserv.NewMemStore(), putErr: errInjected}
	fs.MemStore.Put(context.Background(), storeNamespace, "state", raw) //nolint:errcheck
	if err := (&Provider{Log: testLog(), Store: fs}).Init(); !errors.Is(err, errInjected) {
		t.Fatalf("Init with failing save = %v", err)
	}
}

// An uninitialised provider has no id and says so.
func TestWhoAmIBeforeInit(t *testing.T) {
	p := &Provider{Log: testLog()}
	if id, eph, _ := p.WhoAmI(context.Background()); id != "" || !eph || p.Enrolled() {
		t.Fatalf("before Init: %q eph=%v enrolled=%v", id, eph, p.Enrolled())
	}
}

// A device id recorded in the state is reported as-is, not ephemeral.
func TestRecordedIdentityLoads(t *testing.T) {
	store := hostserv.NewMemStore()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(identityState{
		DeviceID: "device-1", Tenant: "acme",
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	})
	store.Put(context.Background(), storeNamespace, "state", raw) //nolint:errcheck
	p := &Provider{Log: testLog(), Store: store}
	if err := p.Init(); err != nil {
		t.Fatal(err)
	}
	id, eph, tenant := p.WhoAmI(context.Background())
	if id != "device-1" || eph || tenant != "acme" || !p.Enrolled() {
		t.Fatalf("recorded identity: %s eph=%v tenant=%q", id, eph, tenant)
	}
	if !priv.Equal(p.priv) {
		t.Fatal("stored key not loaded")
	}
}

func TestCredentialFailsClosed(t *testing.T) {
	p := &Provider{Log: testLog(), Store: hostserv.NewMemStore()}
	if err := p.Init(); err != nil {
		t.Fatal(err)
	}
	// Until real, verifiable, issuer-signed semantics exist, Credential
	// must fail closed rather than mint a forgeable token that echoes the
	// requested scopes as granted.
	token, _, granted, err := p.Credential(
		context.Background(),
		"weave-linux-presence",
		[]string{"telemetry:write"},
	)
	if err == nil {
		t.Fatalf(
			"Credential returned a token (%q, granted=%v); it must fail closed",
			token,
			granted,
		)
	}
}

// failingStore fails the operations it is told to, so persistence failures
// at Init surface rather than vanish.
type failingStore struct {
	*hostserv.MemStore
	getErr, putErr error
}

func (s *failingStore) Get(ctx context.Context, m, k string) ([]byte, bool, error) {
	if s.getErr != nil {
		return nil, false, s.getErr
	}
	return s.MemStore.Get(ctx, m, k)
}

func (s *failingStore) Put(ctx context.Context, m, k string, v []byte) error {
	if s.putErr != nil {
		return s.putErr
	}
	return s.MemStore.Put(ctx, m, k, v)
}

func TestInitSurfacesStoreFailures(t *testing.T) {
	p := &Provider{
		Log:   testLog(),
		Store: &failingStore{MemStore: hostserv.NewMemStore(), getErr: errInjected},
	}
	if err := p.Init(); !errors.Is(err, errInjected) {
		t.Fatalf("Init with failing Get = %v", err)
	}
	p = &Provider{
		Log:   testLog(),
		Store: &failingStore{MemStore: hostserv.NewMemStore(), putErr: errInjected},
	}
	if err := p.Init(); !errors.Is(err, errInjected) {
		t.Fatalf("Init with failing Put = %v", err)
	}
}

// Corrupt state is discarded for a fresh key rather than failing startup:
// an unreadable identity must not keep the agent down.
func TestInitReplacesCorruptState(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":  `{`,
		"bad key":   `{"device_id":"d","private_key":"!!"}`,
		"short key": `{"device_id":"d","private_key":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`,
		"no state":  "",
	} {
		t.Run(name, func(t *testing.T) {
			store := hostserv.NewMemStore()
			if raw != "" {
				store.Put(
					context.Background(),
					storeNamespace,
					"state",
					[]byte(raw),
				) //nolint:errcheck
			}
			p := &Provider{Log: testLog(), Store: store}
			if err := p.Init(); err != nil {
				t.Fatal(err)
			}
			id, _, _ := p.WhoAmI(context.Background())
			if id != deriveDeviceID(p.priv) || len(p.priv) != ed25519.PrivateKeySize {
				t.Fatalf("id=%s key=%d bytes", id, len(p.priv))
			}
		})
	}
}

// A disabled provider serves no identity and says why, even after one was
// loaded: nothing from a store core has stopped trusting is handed out.
func TestDisable(t *testing.T) {
	p := &Provider{Log: testLog(), Store: hostserv.NewMemStore()}
	if err := p.Init(); err != nil {
		t.Fatal(err)
	}
	if p.Unavailable() != nil {
		t.Fatal("a loaded identity reported unavailable")
	}
	p.Disable(errInjected)
	if !errors.Is(p.Unavailable(), errInjected) || p.Enrolled() {
		t.Fatalf("Unavailable = %v, enrolled %v", p.Unavailable(), p.Enrolled())
	}
	if id, _, _ := p.WhoAmI(context.Background()); id != "" {
		t.Fatalf("disabled identity answered %q", id)
	}
}
