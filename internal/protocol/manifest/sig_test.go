package manifest

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSigningMessageSeparatesDomains(t *testing.T) {
	data := []byte("file")
	e := SigningMessage(EndorseContext, data)
	m := SigningMessage(ManifestContext, data)
	if bytes.Equal(e, m) {
		t.Fatal("endorsement and manifest messages collide")
	}
	if want := append([]byte(EndorseContext+"\x00"), data...); !bytes.Equal(e, want) {
		t.Fatalf("message = %q, want %q", e, want)
	}
}

func b64(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)) }

func TestParsePublicKey(t *testing.T) {
	pk, raw, err := ParsePublicKey(
		[]byte(`{"schema":1,"key_id":"k1","public_key":"` + b64(32) + `"}`),
	)
	if err != nil || pk.KeyID != "k1" || len(raw) != 32 {
		t.Fatalf("%+v %d %v", pk, len(raw), err)
	}
	for name, doc := range map[string]string{
		"json":     `{`,
		"schema":   `{"schema":2,"key_id":"k1","public_key":"` + b64(32) + `"}`,
		"key id":   `{"schema":1,"public_key":"` + b64(32) + `"}`,
		"base64":   `{"schema":1,"key_id":"k1","public_key":"!!"}`,
		"key size": `{"schema":1,"key_id":"k1","public_key":"` + b64(31) + `"}`,
	} {
		if _, _, err := ParsePublicKey(
			[]byte(doc),
		); err == nil ||
			!strings.Contains(err.Error(), "public key") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestParseSignature(t *testing.T) {
	sig, raw, err := ParseSignature(
		[]byte(`{"schema":1,"key_id":"k1","signature":"` + b64(64) + `"}`),
	)
	if err != nil || sig.KeyID != "k1" || len(raw) != 64 {
		t.Fatalf("%+v %d %v", sig, len(raw), err)
	}
	for name, doc := range map[string]string{
		"json":     `{`,
		"schema":   `{"schema":0,"key_id":"k1","signature":"` + b64(64) + `"}`,
		"key id":   `{"schema":1,"signature":"` + b64(64) + `"}`,
		"base64":   `{"schema":1,"key_id":"k1","signature":"!!"}`,
		"sig size": `{"schema":1,"key_id":"k1","signature":"` + b64(32) + `"}`,
	} {
		if _, _, err := ParseSignature(
			[]byte(doc),
		); err == nil ||
			!strings.Contains(err.Error(), "signature") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
