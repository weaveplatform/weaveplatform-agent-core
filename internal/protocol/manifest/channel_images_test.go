package manifest

import (
	"strings"
	"testing"
)

const (
	dIndex = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dChild = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func channelWith(images string) []byte {
	return []byte(
		`{"schema":1,"channel":"stable","generated_at":"2026-10-02T00:00:00Z","sequence":3,
		"protocol":{"min":1,"max":1},"core":{"version":"","artifacts":[]},"modules":[]` + images + `}`,
	)
}

func TestParseChannelImages(t *testing.T) {
	c, err := ParseChannel(
		channelWith(`,"images":[{"repository":"weaveplatform/weave-images/ubuntu-24.04",
		"tag":"24.04-20260915-r1","digest":"` + dIndex + `",
		"platforms":[{"os":"linux","arch":"arm64","digest":"` + dChild + `"}],
		"signature":{"provider":"cosign-key","key_id":"hint"},"build_date":"2026-10-02T08:00:00Z"}]`),
	)
	if err != nil {
		t.Fatal(err)
	}
	img, ok := c.Image("weaveplatform/weave-images/ubuntu-24.04", dIndex)
	if !ok || img.Signature.KeyID != "hint" || img.Platforms[0].Digest != dChild {
		t.Fatalf("%+v", img)
	}
	if _, ok := c.Image("", dIndex); !ok {
		t.Fatal("empty repository should match any")
	}
	if _, ok := c.Image("other", dIndex); ok {
		t.Fatal("wrong repository matched")
	}
	if _, ok := c.Image("", dChild); ok {
		t.Fatal("a child digest is not an admitted index")
	}
}

func TestParseChannelWithoutImagesIsUnchanged(t *testing.T) {
	c, err := ParseChannel(channelWith(""))
	if err != nil || len(c.Images) != 0 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestParseChannelRejectsBadImages(t *testing.T) {
	for name, images := range map[string]string{
		"bad digest":          `,"images":[{"repository":"r","tag":"t","digest":"sha256:abc"}]`,
		"missing repository":  `,"images":[{"tag":"t","digest":"` + dIndex + `"}]`,
		"missing tag":         `,"images":[{"repository":"r","digest":"` + dIndex + `"}]`,
		"bad platform digest": `,"images":[{"repository":"r","tag":"t","digest":"` + dIndex + `","platforms":[{"os":"linux","arch":"amd64","digest":"md5:x"}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseChannel(
				channelWith(images),
			); err == nil ||
				!strings.Contains(err.Error(), "image") {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}
