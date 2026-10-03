package supervise

import (
	"strings"
	"unicode/utf16"
)

// mergeEnv returns base without the drop keys, then each of add in order;
// a later KEY= replaces an earlier one, so the handshake variables (last)
// always win.
func mergeEnv(base, drop []string, add ...[]string) []string {
	skip := map[string]bool{}
	for _, k := range drop {
		skip[k] = true
	}
	var out []string
	idx := map[string]int{}
	put := func(kv string) {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
			return
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	for _, kv := range base {
		if k, _, _ := strings.Cut(kv, "="); !skip[k] {
			put(kv)
		}
	}
	for _, a := range add {
		for _, kv := range a {
			put(kv)
		}
	}
	return out
}

// weaveEnv is core's own WEAVE_* configuration (log level, state dir), which
// modules inherit wherever they run.
func weaveEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "WEAVE_") {
			out = append(out, kv)
		}
	}
	return out
}

// decodeEnvBlock splits a Windows environment block — NUL-terminated
// UTF-16 strings, ended by an empty one.
func decodeEnvBlock(block []uint16) []string {
	var out []string
	start := 0
	for i, c := range block {
		if c != 0 {
			continue
		}
		if i == start {
			break
		}
		out = append(out, string(utf16.Decode(block[start:i])))
		start = i + 1
	}
	return out
}

// encodeEnvBlock is decodeEnvBlock's inverse, for CREATE_UNICODE_ENVIRONMENT.
func encodeEnvBlock(env []string) []uint16 {
	var out []uint16
	for _, kv := range env {
		if kv == "" || strings.IndexByte(kv, 0) >= 0 {
			continue
		}
		out = append(out, utf16.Encode([]rune(kv))...)
		out = append(out, 0)
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	return append(out, 0)
}
