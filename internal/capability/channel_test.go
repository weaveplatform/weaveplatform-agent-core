package capability

import (
	"errors"
	"runtime"
	"testing"
)

func TestParseChannel(t *testing.T) {
	for _, c := range []struct {
		in, goos string
		want     Channel
	}{
		{"", "linux", Channel{Kind: ChannelAuto}},
		{" auto ", "darwin", Channel{Kind: ChannelAuto}},
		{"virtio-serial", "windows", Channel{Kind: ChannelVirtioSerial}},
		{"vsock:2010", "linux", Channel{Kind: ChannelVsock, Port: 2010}},
		{"hvsocket:2010", "windows", Channel{Kind: ChannelHvSocket, Port: 2010}},
	} {
		got, err := parseChannel(c.in, c.goos)
		if err != nil || got != c.want {
			t.Errorf("parseChannel(%q, %s) = %+v, %v; want %+v", c.in, c.goos, got, err, c.want)
		}
	}
}

// Every refusal is ErrChannelConfig, so core can log it and run without a
// channel rather than guessing at what the operator meant.
func TestParseChannelRefuses(t *testing.T) {
	for _, c := range []struct{ in, goos string }{
		{"serial", "linux"},
		{"vsock", "linux"},
		{"vsock:", "linux"},
		{"vsock:x", "linux"},
		{"vsock:0", "linux"},
		{"vsock:4294967295", "linux"},
		{"vsock:4294967296", "linux"},
		{"vsock:2010", "windows"},
		{"vsock:2010", "darwin"},
		{"hvsocket:2010", "linux"},
	} {
		if got, err := parseChannel(c.in, c.goos); !errors.Is(err, ErrChannelConfig) {
			t.Errorf(
				"parseChannel(%q, %s) = %+v, %v; want ErrChannelConfig",
				c.in,
				c.goos,
				got,
				err,
			)
		}
	}
}

func TestParseChannelUsesThisOS(t *testing.T) {
	_, err := ParseChannel("vsock:2010")
	if (err == nil) != (runtime.GOOS == "linux") {
		t.Fatalf("ParseChannel(vsock:2010) on %s: %v", runtime.GOOS, err)
	}
}

func TestChannelString(t *testing.T) {
	if s := (Channel{Kind: ChannelVsock, Port: 2010}).String(); s != "vsock:2010" {
		t.Errorf("String = %q", s)
	}
	if s := (Channel{Kind: ChannelAuto}).String(); s != "auto" {
		t.Errorf("String = %q", s)
	}
}

// ChannelNone is what a refused configuration becomes: whatever this host
// would otherwise have found, no channel is claimed.
func TestProbeWithNoneClaimsNoChannel(t *testing.T) {
	set := ProbeWith(Channel{Kind: ChannelNone})
	if _, ok := set["hypervisor.channel"]; ok {
		t.Fatalf("claimed a channel with none configured: %v", set["hypervisor.channel"])
	}
	if _, ok := set["platform.osinfo"]; !ok {
		t.Fatal("platform.osinfo missing")
	}
}

func TestParseUnixChannel(t *testing.T) {
	for _, c := range []struct {
		in, goos, path string
	}{
		{"unix:/run/weave/channel.sock", "linux", "/run/weave/channel.sock"},
		{"unix:/var/run/weave.sock", "darwin", "/var/run/weave.sock"},
		{`unix:C:\ProgramData\weave\channel.sock`, "windows", `C:\ProgramData\weave\channel.sock`},
		{`unix:\\?\C:\weave\channel.sock`, "windows", `\\?\C:\weave\channel.sock`},
	} {
		got, err := parseChannel(c.in, c.goos)
		if err != nil || got != (Channel{Kind: ChannelUnix, Path: c.path}) {
			t.Errorf("parseChannel(%q, %s) = %+v, %v", c.in, c.goos, got, err)
		}
		if got.String() != c.in {
			t.Errorf("String() = %q, want %q", got.String(), c.in)
		}
	}
	for _, c := range []struct{ in, goos string }{
		{"unix", "linux"},
		{"unix:", "linux"},
		{"unix:run/weave.sock", "linux"},
		{`unix:C:\weave.sock`, "linux"},
		{"unix:/run/weave.sock", "windows"},
		{`unix:C:weave.sock`, "windows"},
	} {
		if got, err := parseChannel(c.in, c.goos); !errors.Is(err, ErrChannelConfig) {
			t.Errorf(
				"parseChannel(%q, %s) = %+v, %v; want ErrChannelConfig",
				c.in,
				c.goos,
				got,
				err,
			)
		}
	}
}

// A unix channel is claimed on every OS without probing: core creates the
// socket itself.
func TestProbeWithUnixClaimsTheSocket(t *testing.T) {
	set := ProbeWith(Channel{Kind: ChannelUnix, Path: "/run/weave/channel.sock"})
	got := set["hypervisor.channel"]
	if got["kind"] != ChannelUnix || got["path"] != "/run/weave/channel.sock" {
		t.Fatalf("hypervisor.channel = %v", got)
	}
	if _, ok := set["platform.osinfo"]; !ok {
		t.Fatal("platform.osinfo missing")
	}
}
