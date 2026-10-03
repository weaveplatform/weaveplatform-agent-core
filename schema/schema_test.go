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
	raw, err := os.ReadFile("channel-manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("channel.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("channel.json")
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
