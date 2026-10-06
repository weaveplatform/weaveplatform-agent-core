package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/weaveplatform/weaveplatform-agent-core/internal/gen/go/weave/control/v1"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/identity"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

// signedChannel serves a genuine, fresh channel manifest bundle signed under a
// root key it returns as core's embedded root key JSON.
func signedChannel(t *testing.T, sequence uint64) (url string, rootJSON []byte) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := func(id string, pub ed25519.PublicKey) []byte {
		b, err := json.Marshal(manifest.PublicKey{
			Schema: 1, KeyID: id, PublicKey: base64.StdEncoding.EncodeToString(pub),
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sig := func(id string, priv ed25519.PrivateKey, ctx string, msg []byte) []byte {
		b, err := json.Marshal(manifest.Signature{
			Schema: 1, KeyID: id,
			Signature: base64.StdEncoding.EncodeToString(
				ed25519.Sign(priv, manifest.SigningMessage(ctx, msg))),
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	signingKey := key("signing", signPub)
	mb, err := json.Marshal(manifest.ChannelManifest{
		Schema: 1, Channel: "stable", Sequence: sequence, GeneratedAt: "2026-08-10T00:00:00Z",
		Protocol: manifest.ProtocolWindow{Min: 1, Max: 1},
		Core:     manifest.ChannelCore{Version: "0.1.0", Artifacts: []manifest.ChannelArtifact{}},
		Modules:  []manifest.ChannelModule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"manifest.json":     mb,
		"manifest.json.sig": sig("signing", signPriv, manifest.ManifestContext, mb),
		"signing.pub":       signingKey,
		"signing.pub.sig":   sig("root", rootPriv, manifest.EndorseContext, signingKey),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/", key("root", rootPub)
}

func useRootKey(t *testing.T, rootJSON []byte) {
	t.Helper()
	old := embeddedRootPub
	embeddedRootPub = rootJSON
	t.Cleanup(func() { embeddedRootPub = old })
}

func countLines(r *recorder, s string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, l := range r.lines {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

// The sysprep clone: store.key does not unseal. Core comes up instead of
// exiting, says why at ERROR (again, periodically), reports itself degraded
// on the control surface, refuses a genuine channel manifest, and leaves the
// store files exactly where they were.
func TestRunDegradedWhenTheStoreDoesNotUnseal(t *testing.T) {
	dir := stateDir(t)
	isolate(t, baseCaps())
	for _, name := range []string{"store.key", "store.db"} {
		writeFile(t, filepath.Join(dir, name), "sealed on the template")
	}
	unseal := errors.New("DPAPI: the data is invalid")
	origOpen, origRepeat := openStore, degradedRepeat
	openStore = func(string) (*store.Store, error) {
		return nil, errors.Join(store.ErrUnseal, unseal)
	}
	degradedRepeat = 20 * time.Millisecond
	t.Cleanup(func() { openStore, degradedRepeat = origOpen, origRepeat })
	url, rootJSON := signedChannel(t, 7)
	useRootKey(t, rootJSON)

	rec := &recorder{}
	client, stop := startCore(t, Options{
		StateDir:    dir,
		ManifestURL: url,
		Log:         slog.New(slog.NewTextHandler(rec, nil)),
	})
	ctx := context.Background()

	st, err := client.Status(ctx, &controlv1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	c := st.GetCore()
	if !c.GetDegraded() || st.GetDeviceId() != "" || st.GetEnrolled() ||
		!strings.Contains(c.GetReason(), "weave seal") ||
		!strings.Contains(c.GetReason(), "delete store.key and store.db from "+dir) ||
		strings.Join(c.GetUnavailable(), ",") != strings.Join(degradedFeatures, ",") {
		t.Fatalf("Status = %v", st)
	}

	_, err = client.Install(ctx, &controlv1.InstallRequest{ModuleId: "anything"})
	if err == nil || !strings.Contains(err.Error(), "anti-rollback mark cannot be read") {
		t.Fatalf("Install = %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for countLines(rec, "core is running degraded") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the degraded ERROR was not repeated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := stop(); err != nil {
		t.Fatalf("Run = %v", err)
	}
	for _, want := range []string{
		"level=ERROR",
		"different machine or user identity",
		// The path itself is checked in Status: the text handler escapes a
		// Windows path's backslashes in the log.
		"delete store.key and store.db from ",
		"keep manifest.sequence",
		"DPAPI: the data is invalid",
	} {
		if !rec.has(want) {
			t.Errorf("log lacks %q", want)
		}
	}
	for _, name := range []string{"store.key", "store.db"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil ||
			string(b) != "sealed on the template" {
			t.Errorf("%s was touched: %q, %v", name, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.sequence")); !os.IsNotExist(err) {
		t.Errorf("a refused manifest wrote the mark: %v", err)
	}
}

// A store.db kept beside a new store.key opens, but the identity in it does
// not decrypt. Core runs degraded rather than writing a fresh identity over
// the old one.
func TestRunDegradedWhenTheIdentityDoesNotDecrypt(t *testing.T) {
	isolate(t, baseCaps())
	dir := stateDir(t)
	quiet := slog.New(slog.DiscardHandler)
	st, err := store.Open(dir, keyprotect.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := (&identity.Provider{Log: quiet, Store: st}).Init(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.Remove(filepath.Join(dir, "store.key")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}

	rec := &recorder{}
	client, stop := startCore(t, Options{StateDir: dir, Log: slog.New(slog.NewTextHandler(rec, nil))})
	status, err := client.Status(context.Background(), &controlv1.StatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !status.GetCore().GetDegraded() || status.GetDeviceId() != "" {
		t.Fatalf("Status = %v", status)
	}
	if err := stop(); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if !rec.has("different machine or user identity") {
		t.Error("log does not name the likely cause")
	}
	after, err := os.ReadFile(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("store.db changed under a degraded core")
	}
}

// A store that fails for some other reason is degraded too, without blaming a
// clone.
func TestDegradedReasonForAnUnreadableStore(t *testing.T) {
	r := degradedReason("/var/lib/weave", errors.New("store: reading master key: permission denied"))
	if strings.Contains(r, "weave seal") || !strings.Contains(r, "unreadable or damaged") ||
		!strings.Contains(r, "/var/lib/weave") {
		t.Fatalf("reason = %s", r)
	}
}
