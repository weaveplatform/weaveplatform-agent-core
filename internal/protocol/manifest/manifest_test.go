package manifest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/protocol/hvchannel"
)

const validManifest = `{"schema":1,"id":"weave-linux-presence","version":"1.2.3","protocol":1,"zone":"A",
	"privilege":"service","session":"system",
	"platforms":[{"os":"darwin","arch":"arm64"},{"os":"linux","arch":"amd64"}],
	"artifacts":[{"os":"linux","arch":"amd64","digest":"` + dIndex + `","size":10}]}`

func TestParseValidManifest(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "weave-linux-presence" || m.Version != "1.2.3" || len(m.Artifacts) != 1 {
		t.Fatalf("got %+v", m)
	}
	if !m.SupportsHost("linux", "amd64") || m.SupportsHost("windows", "amd64") {
		t.Fatal("SupportsHost wrong")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"schema":`)); err == nil {
		t.Fatal("accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() Manifest {
		return Manifest{
			Schema: 1, ID: "weave-linux-presence", Version: "1.0.0", Protocol: 1, Zone: "B",
			Privilege: PrivilegeUser, Session: SessionPerUserAll,
			Platforms: []Platform{{OS: "windows", Arch: "arm64"}},
		}
	}
	for name, mutate := range map[string]func(*Manifest){
		"schema":          func(m *Manifest) { m.Schema = 2 },
		"id":              func(m *Manifest) { m.ID = "Sys_Info" },
		"reserved id":     func(m *Manifest) { m.ID = "hvchannel" },
		"version":         func(m *Manifest) { m.Version = "1.0" },
		"protocol":        func(m *Manifest) { m.Protocol = 0 },
		"zone":            func(m *Manifest) { m.Zone = "D" },
		"privilege":       func(m *Manifest) { m.Privilege = "root" },
		"session":         func(m *Manifest) { m.Session = "any" },
		"no platforms":    func(m *Manifest) { m.Platforms = nil },
		"platform os":     func(m *Manifest) { m.Platforms[0].OS = "plan9" },
		"platform arch":   func(m *Manifest) { m.Platforms[0].Arch = "386" },
		"artifact os":     func(m *Manifest) { m.Artifacts = []Artifact{{OS: "bsd", Arch: "amd64", Digest: dIndex}} },
		"artifact digest": func(m *Manifest) { m.Artifacts = []Artifact{{OS: "linux", Arch: "amd64", Digest: "sha256:x"}} },
		"thumbprint":      func(m *Manifest) { m.Signing = &Signing{AuthenticodeThumbprint: "A6:A3"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatalf("accepted %+v", m)
			}
		})
	}
	m := base()
	m.Session = SessionPerUserConsole
	m.Privilege = PrivilegeSystem
	m.Zone = "C"
	m.Version = "2.0.0-rc.1"
	m.Signing = &Signing{AuthenticodeThumbprint: "a6a3936288b9409ed7a3458cf81014a77ab59b51"}
	if err := m.Validate(); err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module.manifest.json")
	if err := os.WriteFile(path, []byte(validManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("missing file loaded")
	}
}

const validChannel = `{"schema":1,"channel":"stable","generated_at":"2026-10-02T00:00:00Z","sequence":7,
	"protocol":{"min":1,"max":2},
	"core":{"version":"1.0.0","artifacts":[]},
	"modules":[{"id":"weave-linux-presence","version":"1.2.3","protocol":1,"privilege":"service","session":"system",
		"capabilities":["platform.osinfo"],"subscribes":["a.*"],
		"artifacts":[{"os":"linux","arch":"amd64","url":"https://x","digest":"` + dIndex + `","size":1}]}]}`

func TestParseChannelAndLookups(t *testing.T) {
	c, err := ParseChannel([]byte(validChannel))
	if err != nil {
		t.Fatal(err)
	}
	cm, ok := c.Module("weave-linux-presence")
	if !ok {
		t.Fatal("module not found")
	}
	if _, ok := c.Module("absent"); ok {
		t.Fatal("absent module found")
	}
	platforms := []Platform{{OS: "linux", Arch: "amd64"}}
	m := cm.ModuleManifest(platforms)
	if err := m.Validate(); err != nil {
		t.Fatalf("converted manifest invalid: %v", err)
	}
	if m.ID != "weave-linux-presence" || m.Zone != "A" || m.Subscribes[0] != "a.*" {
		t.Fatalf("converted = %+v", m)
	}
}

func TestParseChannelRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"json":           `{"schema":`,
		"schema":         strings.Replace(validChannel, `"schema":1`, `"schema":2`, 1),
		"no channel":     strings.Replace(validChannel, `"channel":"stable"`, `"channel":""`, 1),
		"zero min":       strings.Replace(validChannel, `"min":1`, `"min":0`, 1),
		"inverted":       strings.Replace(validChannel, `"max":2`, `"max":0`, 1),
		"traversal id":   strings.Replace(validChannel, `"id":"weave-linux-presence"`, `"id":"../../etc"`, 1),
		"module version": strings.Replace(validChannel, `"version":"1.2.3"`, `"version":"latest"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseChannel([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestExpired(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for expires, want := range map[string]bool{
		"":                     false,
		"2026-10-03T00:00:00Z": false,
		"2026-10-01T00:00:00Z": true,
		"next tuesday":         true,
	} {
		c := ChannelManifest{Expires: expires}
		if got := c.Expired(now); got != want {
			t.Errorf("Expires %q: Expired = %v, want %v", expires, got, want)
		}
	}
}

func TestArtifactForHost(t *testing.T) {
	arts := []ChannelArtifact{
		{OS: "plan9", Arch: "mips"},
		{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "here"},
	}
	a, ok := ArtifactForHost(arts)
	if !ok || a.URL != "here" {
		t.Fatalf("got %+v, %v", a, ok)
	}
	if _, ok := ArtifactForHost(arts[:1]); ok {
		t.Fatal("matched a foreign artifact")
	}
}

func TestChannelAddress(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.ChannelAddress(); got != "weave-linux-presence" {
		t.Fatalf("no address: ChannelAddress = %q, want the id", got)
	}
	m.Address = "weave.exec"
	if err := m.Validate(); err != nil {
		t.Fatalf("dotted address refused: %v", err)
	}
	if got := m.ChannelAddress(); got != "weave.exec" {
		t.Fatalf("ChannelAddress = %q", got)
	}
	for _, bad := range []string{"Weave.exec", "weave..exec", ".exec", "exec.", "weave exec", hvchannel.ControlModule} {
		m.Address = bad
		if err := m.Validate(); err == nil {
			t.Errorf("address %q accepted", bad)
		}
	}
}
