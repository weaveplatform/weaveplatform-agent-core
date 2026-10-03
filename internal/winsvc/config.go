// Package winsvc runs weaveboot as a Windows service and registers it with
// the Service Control Manager — the Windows counterpart of the systemd unit
// (packaging/linux/weave-agent.service) and the launchd plist.
//
// Everything that can be decided without the SCM — the command line, the
// environment encoding, the service-handler state machine, the install
// sequence — lives in OS-neutral files so every CI lane tests it. The SCM,
// registry and ACL calls sit behind the Manager seam in *_windows.go.
package winsvc

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// Defaults for the agent's service registration.
const (
	DefaultName        = "WeaveAgent"
	DefaultDisplayName = "Weave platform agent"
	DefaultDescription = "Supervises the Weave platform agent core (weave-agent) and its modules."
)

// Recovery mirrors the systemd unit: Restart=always, RestartSec=2, and
// TimeoutStopSec=30 as the preshutdown budget.
const (
	RestartDelay       = 2 * time.Second
	PreshutdownTimeout = 30 * time.Second
	// FailureResetPeriod only governs which of the (identical) restart
	// actions applies; every failure restarts regardless.
	FailureResetPeriod = 24 * time.Hour
)

// Config is the full service registration. Install applies all of it on
// create and on update alike, so a re-install converges an existing service
// on exactly this, rather than layering over what an earlier install left.
type Config struct {
	Name        string
	DisplayName string
	Description string
	// BinaryPath is the absolute path of weaveboot.exe, resolved at install
	// time rather than left as %ProgramFiles%: the install directory is a
	// flag, and the arguments (--modules-dir) must name the same tree.
	BinaryPath string
	Args       []string
	// Env is KEY=VALUE pairs for the service's Environment value, which the
	// SCM merges into the system environment when it starts the process;
	// weaveboot passes its environment on to core.
	Env []string
}

// CommandLine is the ImagePath the SCM launches, quoted per
// CommandLineToArgvW so a path under "Program Files" survives as one argv.
func (c Config) CommandLine() string {
	parts := make([]string, 0, 1+len(c.Args))
	parts = append(parts, quoteArg(c.BinaryPath, true))
	for _, a := range c.Args {
		parts = append(parts, quoteArg(a, false))
	}
	return strings.Join(parts, " ")
}

// ErrInvalidConfig wraps every validation failure.
var ErrInvalidConfig = errors.New("winsvc: invalid configuration")

// Validate rejects a registration the SCM would accept but run wrongly, or
// that the UTF-16 conversions would panic on (an embedded NUL).
func (c Config) Validate() error {
	switch {
	case c.Name == "" || strings.ContainsAny(c.Name, `/\`):
		return fmt.Errorf("%w: service name %q", ErrInvalidConfig, c.Name)
	case c.BinaryPath == "":
		return fmt.Errorf("%w: binary path is required", ErrInvalidConfig)
	}
	for _, s := range append([]string{c.Name, c.DisplayName, c.Description, c.BinaryPath}, c.Args...) {
		if strings.ContainsRune(s, 0) {
			return fmt.Errorf("%w: NUL character", ErrInvalidConfig)
		}
	}
	return ValidateEnv(c.Env)
}

// ValidateEnv checks KEY=VALUE pairs. Duplicate keys are refused rather
// than resolved: which one the SCM would hand the process is not
// documented, and an install flag silently losing to another is the kind of
// mistake that surfaces as a guest that trusts the wrong key.
func ValidateEnv(env []string) error {
	seen := map[string]bool{}
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return fmt.Errorf("%w: environment entry %q is not KEY=VALUE", ErrInvalidConfig, kv)
		}
		if strings.ContainsRune(kv, 0) {
			return fmt.Errorf(
				"%w: environment entry for %s contains a NUL character",
				ErrInvalidConfig,
				k,
			)
		}
		uk := strings.ToUpper(k) // Windows environment names are case-insensitive
		if seen[uk] {
			return fmt.Errorf("%w: environment variable %s given twice", ErrInvalidConfig, k)
		}
		seen[uk] = true
	}
	return nil
}

// EncodeMultiSZ encodes strings as a REG_MULTI_SZ payload: UTF-16LE, each
// string NUL-terminated, the list terminated by one more NUL. An empty list
// encodes to nil — an empty REG_MULTI_SZ is the caller's cue to delete the
// value instead, since a lone terminator is not a well-formed list.
func EncodeMultiSZ(ss []string) []byte {
	if len(ss) == 0 {
		return nil
	}
	var u []uint16
	for _, s := range ss {
		u = append(u, utf16.Encode([]rune(s))...)
		u = append(u, 0)
	}
	u = append(u, 0)
	b := make([]byte, 2*len(u))
	for i, v := range u {
		b[2*i] = byte(v & 0xff)
		b[2*i+1] = byte(v >> 8)
	}
	return b
}

// DecodeMultiSZ is the inverse of EncodeMultiSZ, tolerant of the missing
// final terminator some writers leave.
func DecodeMultiSZ(b []byte) []string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	var out []string
	start := 0
	for i, v := range u {
		if v != 0 {
			continue
		}
		if i == start {
			break
		}
		out = append(out, string(utf16.Decode(u[start:i])))
		start = i + 1
	}
	if start < len(u) && u[len(u)-1] != 0 {
		out = append(out, string(utf16.Decode(u[start:])))
	}
	return out
}

// quoteArg escapes one argument for CommandLineToArgvW. It is a portable
// copy of syscall.EscapeArg (Windows-only), with force set for the program
// name: the SCM parses an unquoted path containing spaces by trying each
// prefix in turn, so "C:\Program Files\Weave\weaveboot.exe" unquoted would
// first try to run C:\Program.exe — the classic unquoted-service-path hole.
func quoteArg(s string, force bool) string {
	if s == "" {
		return `""`
	}
	if !force && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(c)
	}
	b.WriteString(strings.Repeat(`\`, slashes))
	b.WriteByte('"')
	return b.String()
}
