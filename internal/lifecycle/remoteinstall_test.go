package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/manifest"
)

// signedChannel builds a root-endorsed, signing-key-signed channel manifest
// bundle for one module whose single artifact is `artifact`, and returns the
// four bundle files plus the root public key. digest/size describe the
// artifact as the manifest will claim them — callers pass the real values
// for the honest path and lie for the adversarial cases.
func signedChannel(
	t *testing.T,
	artifactURL, digest string,
	size int64,
) (rootPub ed25519.PublicKey, files map[string][]byte) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signingKeyFile, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "signing-2026",
		"public_key": base64.StdEncoding.EncodeToString(signPub),
	})
	endorsement, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "root",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				rootPriv,
				manifest.SigningMessage(manifest.EndorseContext, signingKeyFile),
			),
		),
	})
	ch := manifest.ChannelManifest{
		Schema: 1, Channel: "stable", GeneratedAt: "2026-08-10T00:00:00Z",
		Protocol: manifest.ProtocolWindow{Min: 1, Max: 1},
		Core:     manifest.ChannelCore{Version: "0.1.0", Artifacts: []manifest.ChannelArtifact{}},
		Modules: []manifest.ChannelModule{{
			ID: "testmod", Version: "1.0.0", Protocol: 1,
			Privilege: "service", Session: "system",
			Capabilities: []string{"platform.osinfo"},
			Artifacts: []manifest.ChannelArtifact{{
				OS: runtime.GOOS, Arch: runtime.GOARCH,
				URL: artifactURL, Digest: digest, Size: size,
			}},
		}},
	}
	manifestBytes, _ := json.Marshal(ch)
	manifestSig, _ := json.Marshal(map[string]any{
		"schema": 1, "key_id": "signing-2026",
		"signature": base64.StdEncoding.EncodeToString(
			ed25519.Sign(
				signPriv,
				manifest.SigningMessage(manifest.ManifestContext, manifestBytes),
			),
		),
	})
	return rootPub, map[string][]byte{
		"manifest.json":     manifestBytes,
		"manifest.json.sig": manifestSig,
		"signing.pub":       signingKeyFile,
		"signing.pub.sig":   endorsement,
	}
}

func sha256Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestRemoteInstallRejectsTampering drives Install against an httptest
// origin and asserts that a corrupted artifact or signature is refused and
// leaves no version staged on disk. The honest bundle installs; each attack
// variant fails and the module tree stays empty.
func TestRemoteInstallRejectsTampering(t *testing.T) {
	mgr, sup, bin := newTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup.SetBaseContext(ctx)

	artifact, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	honestDigest := sha256Digest(artifact)
	honestSize := int64(len(artifact))

	cases := []struct {
		name       string
		digest     string // digest the manifest claims
		size       int64  // size the manifest claims
		serveBytes []byte // what the artifact endpoint returns
		corruptSig bool   // flip a byte in manifest.json.sig
		wantErr    bool
	}{
		// Adversarial cases first: each must fail before staging, so the
		// version tree stays empty. The honest install runs last (it does
		// leave a version on disk).
		{
			name:       "wrong-digest",
			digest:     sha256Digest([]byte("not the binary")),
			size:       honestSize,
			serveBytes: artifact,
			wantErr:    true,
		},
		{
			name:       "truncated",
			digest:     honestDigest,
			size:       honestSize,
			serveBytes: artifact[:len(artifact)-1],
			wantErr:    true,
		},
		{
			name:       "oversized",
			digest:     honestDigest,
			size:       honestSize,
			serveBytes: append(append([]byte{}, artifact...), 'x'),
			wantErr:    true,
		},
		{
			name:       "tampered-signature",
			digest:     honestDigest,
			size:       honestSize,
			serveBytes: artifact,
			corruptSig: true,
			wantErr:    true,
		},
		{
			name:       "honest",
			digest:     honestDigest,
			size:       honestSize,
			serveBytes: artifact,
			wantErr:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			var srv *httptest.Server
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				name := filepath.Base(r.URL.Path)
				if name == "artifact.bin" {
					w.Write(tc.serveBytes) //nolint:errcheck
					return
				}
				w.WriteHeader(http.StatusNotFound)
			})
			srv = httptest.NewServer(mux)
			defer srv.Close()

			rootPub, files := signedChannel(t, srv.URL+"/artifact.bin", tc.digest, tc.size)
			if tc.corruptSig {
				files["manifest.json.sig"][len(files["manifest.json.sig"])-4] ^= 0xff
			}
			mux.HandleFunc("/manifest.json", serveBytesHandler(files["manifest.json"]))
			mux.HandleFunc("/manifest.json.sig", serveBytesHandler(files["manifest.json.sig"]))
			mux.HandleFunc("/signing.pub", serveBytesHandler(files["signing.pub"]))
			mux.HandleFunc("/signing.pub.sig", serveBytesHandler(files["signing.pub.sig"]))

			mgr.RootPub = rootPub
			mgr.ManifestURL = srv.URL

			_, err := mgr.Install(ctx, "testmod", "1.0.0")
			if tc.wantErr && err == nil {
				t.Fatalf("%s: Install succeeded, want failure", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("%s: Install failed: %v", tc.name, err)
			}

			if tc.wantErr {
				// The rejected install must leave nothing staged: no version
				// directory under the module tree.
				versions := filepath.Join(mgr.Layout.ModulesDir, "testmod", "versions")
				entries, _ := os.ReadDir(versions)
				if len(entries) != 0 {
					t.Fatalf(
						"%s: %d version dirs staged after a rejected install; staging must be clean",
						tc.name,
						len(entries),
					)
				}
			}
		})
	}
}

func serveBytesHandler(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.Write(b) } //nolint:errcheck
}
