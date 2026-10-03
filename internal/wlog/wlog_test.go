package wlog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNewWritesJSONWithComponent(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelInfo, "weave-linux-presence")
	log.Debug("hidden")
	log.Info("shown", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not one JSON record: %v\n%s", err, buf.Bytes())
	}
	if rec["component"] != "weave-linux-presence" || rec["msg"] != "shown" || rec["k"] != "v" {
		t.Fatalf("record = %v", rec)
	}
}

func TestLevelFromEnv(t *testing.T) {
	for env, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"DEBUG": slog.LevelDebug,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"info":  slog.LevelInfo,
		"":      slog.LevelInfo,
		"loud":  slog.LevelInfo,
	} {
		t.Setenv("WEAVE_LOG_LEVEL", env)
		if got := LevelFromEnv(); got != want {
			t.Errorf("WEAVE_LOG_LEVEL=%q: got %v, want %v", env, got, want)
		}
	}
}

func TestDefaultHonoursLevel(t *testing.T) {
	t.Setenv("WEAVE_LOG_LEVEL", "error")
	log := Default("core")
	if log.Enabled(t.Context(), slog.LevelWarn) {
		t.Fatal("warn enabled at WEAVE_LOG_LEVEL=error")
	}
	if !log.Enabled(t.Context(), slog.LevelError) {
		t.Fatal("error disabled at WEAVE_LOG_LEVEL=error")
	}
}
