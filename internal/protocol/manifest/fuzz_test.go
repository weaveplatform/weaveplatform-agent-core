package manifest

import "testing"

// FuzzManifest asserts the two untrusted-input decoders — Parse (module
// manifest) and ParseChannel (channel manifest) — never panic on arbitrary
// bytes. Both flow signed-but-attacker-influenced JSON into path building
// and filesystem operations downstream, so a panic here is a denial-of-
// service vector; a returned error is the only acceptable failure.
func FuzzManifest(f *testing.F) {
	seeds := []string{
		`{"schema":1,"id":"weave-linux-presence","version":"1.2.3","protocol":1,"zone":"A","privilege":"service","session":"system","platforms":[{"os":"darwin","arch":"arm64"}]}`,
		`{"schema":1,"id":"../evil","version":"1.0.0","protocol":1,"zone":"A","privilege":"service","session":"system","platforms":[{"os":"linux","arch":"amd64"}]}`,
		`{}`,
		``,
		`null`,
		`{"schema":1}`,
		`[1,2,3]`,
		`{"modules":[{"id":"a","version":"1.0.0"}]}`,
		`{"sequence":18446744073709551615,"expires":"not-a-time"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
		_, _ = ParseChannel(data)
	})
}
