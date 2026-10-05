// Package schema_test checks the published JSON Schemas against the
// documents the platform actually produces. Nothing at runtime validates
// against them, so without this test the schema drifts from what CI writes
// (it lacked sequence, expires and subscribes for months).
package schema_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func channelSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return compile(t, "channel-manifest.schema.json")
}

func compile(t *testing.T, file string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(file, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, doc string) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(v)
}

// The seed document weaveplatform-release-channels' promote workflow writes, a
// module promotion as that workflow assembles it, and an image promotion as
// weaveplatform-oci's `weaveoci channel promote` writes it.
var valid = map[string]string{
	"promote seed": `{"schema":1,"channel":"stable","generated_at":"2026-10-02T00:00:00Z","sequence":0,
		"protocol":{"min":1,"max":1},"core":{"version":"","artifacts":[]},"modules":[]}`,
	"module promotion": `{"schema":1,"channel":"stable","generated_at":"2026-10-02T00:00:00Z","sequence":7,
		"expires":"2026-11-01T00:00:00Z","protocol":{"min":1,"max":1},"core":{"version":"","artifacts":[]},
		"modules":[{"id":"weave-linux-presence","version":"0.3.0","protocol":1,"privilege":"service","session":"system",
		"capabilities":[],"subscribes":["inventory"],
		"artifacts":[{"os":"linux","arch":"arm64","url":"ghcr.io/weaveplatform/weaveplatform-modules/weave-linux-presence:0.3.0#linux-arm64","digest":"` + d1 + `","size":10}]}]}`,
	"image promotion": `{"schema":1,"channel":"org-images","generated_at":"2026-10-02T00:00:00Z","sequence":1,
		"protocol":{"min":1,"max":1},"core":{"version":"","artifacts":[]},"modules":[],
		"images":[{"repository":"weaveplatform/weave-images/ubuntu-24.04","tag":"24.04-20260915-r1","digest":"` + d1 + `",
		"platforms":[{"os":"linux","arch":"arm64","digest":"` + d2 + `"},{"os":"windows","arch":"amd64","os_version":"10.0.26200.6584","digest":"` + d2 + `"}],
		"signature":{"provider":"cosign-key","key_id":"hint"},"build_date":"2026-10-02T08:00:00Z"}]}`,
}

// A Windows module's distribution entry, signing pinned as the
// weave-windows-* manifests pin it and weaveplatform-release-channels copies
// it into the channel.
const thumb = "A6A3936288B9409ED7A3458CF81014A77AB59B51"

func init() {
	valid["windows module promotion"] = strings.Replace(valid["module promotion"],
		`"subscribes":["inventory"],`,
		`"subscribes":["inventory"],"signing":{"authenticode_subject":"weaveplatform code signing","authenticode_thumbprint":"`+thumb+`"},`, 1)
}

func TestChannelSchemaAcceptsProducedDocuments(t *testing.T) {
	s := channelSchema(t)
	for name, doc := range valid {
		t.Run(name, func(t *testing.T) {
			if err := validate(t, s, doc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestChannelSchemaRejects(t *testing.T) {
	s := channelSchema(t)
	base := valid["image promotion"]
	for name, doc := range map[string]string{
		"unknown top-level field": strings.Replace(base, `"sequence":1`, `"sequence":1,"surprise":true`, 1),
		"bad image digest":        strings.Replace(base, `"digest":"`+d1+`"`, `"digest":"sha256:abc"`, 1),
		"unknown signer":          strings.Replace(base, `"provider":"cosign-key"`, `"provider":"pgp"`, 1),
		"unknown image field":     strings.Replace(base, `"tag":"24.04-20260915-r1"`, `"tag":"24.04-20260915-r1","ecid":"x"`, 1),
		"negative sequence":       strings.Replace(base, `"sequence":1`, `"sequence":-1`, 1),
		"bad expiry":              strings.Replace(base, `"sequence":1`, `"sequence":1,"expires":"soon"`, 1),
		"short thumbprint":        strings.Replace(valid["windows module promotion"], thumb, thumb[:39], 1),
		"module without artifacts": strings.Replace(valid["module promotion"],
			`"artifacts":[{"os":"linux"`, `"artifacts":[],"x":[{"os":"linux"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(t, s, doc); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A module manifest as agent-modules writes one for Windows (the
// weave-windows-presence manifest), and the ways its signing pin can be
// malformed.
const windowsModule = `{"schema":1,"id":"weave-windows-presence","version":"0.2.0","protocol":1,"zone":"A",
	"privilege":"service","session":"system",
	"platforms":[{"os":"windows","arch":"amd64"},{"os":"windows","arch":"arm64"}],
	"capabilities":["hypervisor.channel"],"address":"weave.presence",
	"signing":{"authenticode_subject":"weaveplatform code signing","authenticode_thumbprint":"` + thumb + `"}}`

func TestModuleSchemaSigning(t *testing.T) {
	s := compile(t, "module-manifest.schema.json")
	for name, doc := range map[string]string{
		"both":            windowsModule,
		"thumbprint only": strings.Replace(windowsModule, `"authenticode_subject":"weaveplatform code signing",`, "", 1),
		"lower case":      strings.Replace(windowsModule, thumb, strings.ToLower(thumb), 1),
	} {
		if err := validate(t, s, doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"39 digits":     strings.Replace(windowsModule, thumb, thumb[:39], 1),
		"41 digits":     strings.Replace(windowsModule, thumb, thumb+"0", 1),
		"not hex":       strings.Replace(windowsModule, thumb, "Z"+thumb[1:], 1),
		"colons":        strings.Replace(windowsModule, thumb, "A6:"+thumb[2:], 1),
		"unknown field": strings.Replace(windowsModule, `"signing":{`, `"signing":{"authenticode_issuer":"x",`, 1),
	} {
		if err := validate(t, s, doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
