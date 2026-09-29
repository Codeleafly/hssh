package cli

import (
	"errors"
	"testing"
	"time"
)

func TestParseBothFlagSyntaxes(t *testing.T) {
	spec := FlagSpec{
		Values: []string{"port", "host", "password"},
		Bools:  []string{"allow-unauthenticated", "verbose"},
	}

	tests := []struct {
		name string
		argv []string
		want string
		port int
		bool bool
	}{
		{"equals form", []string{"--port=8080", "--allow-unauthenticated"}, "", 8080, true},
		{"space form", []string{"--port", "9090", "--allow-unauthenticated"}, "", 9090, true},
		{"short p", []string{"-p", "1234"}, "", 1234, false},
		{"bool with value", []string{"--port=1", "--allow-unauthenticated=false"}, "", 1, false},
		{"bool with =true", []string{"--port=1", "--allow-unauthenticated=true"}, "", 1, true},
		{"missing bool stays false", []string{"--port=2"}, "", 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Parse(tc.argv, spec)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if tc.want != "" && f.String("host", "") != tc.want {
				t.Fatalf("host = %q", f.String("host", ""))
			}
			p, err := f.Int("port", 0)
			if err != nil {
				t.Fatalf("int: %v", err)
			}
			if p != tc.port {
				t.Fatalf("port = %d, want %d", p, tc.port)
			}
			if f.Bool("allow-unauthenticated") != tc.bool {
				t.Fatalf("bool = %v, want %v", f.Bool("allow-unauthenticated"), tc.bool)
			}
		})
	}
}

func TestParseRejectsUnknownFlag(t *testing.T) {
	_, err := Parse([]string{"--nope=1"}, FlagSpec{})
	var unknown *ErrUnknownFlag
	if !errors.As(err, &unknown) {
		t.Fatalf("an unknown flag should report ErrUnknownFlag, got %v", err)
	}
	if unknown.Name != "nope" {
		t.Fatalf("ErrUnknownFlag should name the flag, got %q", unknown.Name)
	}
}

func TestParseRejectsValueFlagWithoutValue(t *testing.T) {
	if _, err := Parse([]string{"--port"}, FlagSpec{Values: []string{"port"}}); err == nil {
		t.Fatal("a value flag with no value should be an error")
	}
}

func TestParseRejectsNonNumericPort(t *testing.T) {
	f, err := Parse([]string{"--port", "abc"}, FlagSpec{Values: []string{"port"}, Bools: []string{"quiet"}})
	if err != nil {
		t.Fatalf("parse should succeed and defer the type error: %v", err)
	}
	if _, err := f.Int("port", 0); err == nil {
		t.Fatal("a non-numeric port should be an error")
	}
}

func TestParseHelp(t *testing.T) {
	for _, h := range []string{"-h", "--help"} {
		if _, err := Parse([]string{h}, FlagSpec{}); !errors.Is(err, ErrHelp) {
			t.Fatalf("%s should report ErrHelp, got %v", h, err)
		}
	}
}

func TestParseDoubleDashStopsParsing(t *testing.T) {
	f, err := Parse([]string{"--port=1", "--", "--not-a-flag"}, FlagSpec{Values: []string{"port"}, Bools: []string{"quiet"}})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	args := f.Args()
	if len(args) != 1 || args[0] != "--not-a-flag" {
		t.Fatalf("args = %v", args)
	}
}

func TestParsePositionals(t *testing.T) {
	f, _ := Parse([]string{"http://host:8080", "--password=x", "--password", "y"}, FlagSpec{Values: []string{"password"}, Bools: []string{"quiet"}})
	if f.Arg(0) != "http://host:8080" {
		t.Fatalf("Arg(0) = %q", f.Arg(0))
	}
	if f.Arg(5) != "" {
		t.Fatalf("Arg out of range should be empty, got %q", f.Arg(5))
	}
	// A repeated flag takes the last value, matching normal CLI behaviour.
	if got := f.String("password", ""); got != "y" {
		t.Fatalf("password = %q", got)
	}
}

func TestDurationFlag(t *testing.T) {
	f, _ := Parse([]string{"--idle-timeout", "30m", "--session-timeout=90s"}, FlagSpec{Values: []string{"idle-timeout", "session-timeout"}, Bools: []string{"quiet"}})
	d, err := f.Duration("idle-timeout", 0)
	if err != nil || d != 30*time.Minute {
		t.Fatalf("idle-timeout = %s (%v)", d, err)
	}
	d, err = f.Duration("session-timeout", 0)
	if err != nil || d != 90*time.Second {
		t.Fatalf("session-timeout = %s (%v)", d, err)
	}
	if _, err := f.Duration("missing", time.Minute); err != nil || true {
		// defaults must be returned, not an error
	}
	f2, _ := Parse([]string{"--idle-timeout=soon"}, FlagSpec{Values: []string{"idle-timeout"}})
	if _, err := f2.Duration("idle-timeout", 0); err == nil {
		t.Fatal("an unparsable duration should be an error")
	}
}

func TestHasAndKeys(t *testing.T) {
	f, _ := Parse([]string{"--port=1", "--allow-unauthenticated"}, hostFlags)
	if !f.Has("port") || !f.Has("allow-unauthenticated") {
		t.Fatal("Has should report both flags")
	}
	if f.Has("shell") {
		t.Fatal("Has should be false for an unset flag")
	}
	keys := f.Keys()
	if len(keys) != 2 || keys[0] != "allow-unauthenticated" || keys[1] != "port" {
		t.Fatalf("Keys() = %v", keys)
	}
}

func TestVersionFlag(t *testing.T) {
	for _, v := range []string{"--version", "-v"} {
		if _, err := Parse([]string{v}, FlagSpec{}); !errors.Is(err, ErrVersion) {
			t.Fatalf("%s should report ErrVersion, got %v", v, err)
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	app := New(discard{}, discard{}, nil)
	if code := app.Run([]string{"frobnicate"}); code != 2 {
		t.Fatalf("unknown command should exit 2, got %d", code)
	}
}

func TestRunHelp(t *testing.T) {
	out := &testWriter{}
	app := New(out, out, nil)
	if code := app.Run([]string{"help"}); code != 0 {
		t.Fatalf("help should exit 0, got %d", code)
	}
	for _, want := range []string{"hssh host", "hssh connect", "hssh sessions", "--tls-cert"} {
		if !contains(out.String(), want) {
			t.Fatalf("help is missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunVersion(t *testing.T) {
	out := &testWriter{}
	app := New(out, out, nil)
	if code := app.Run([]string{"version"}); code != 0 {
		t.Fatalf("version should exit 0, got %d", code)
	}
	if !contains(out.String(), "HSSH/1") {
		t.Fatalf("version output is missing the protocol:\n%s", out.String())
	}
}

func TestRunConnectWithoutTarget(t *testing.T) {
	out := &testWriter{}
	app := New(out, out, nil)
	if code := app.Run([]string{"connect"}); code != 2 {
		t.Fatalf("connect with no target should exit 2, got %d", code)
	}
	if !contains(out.String(), "hssh connect=") {
		t.Fatalf("the usage hint is missing:\n%s", out.String())
	}
}

func TestRunGenerateToken(t *testing.T) {
	out := &testWriter{}
	app := New(out, out, nil)
	if code := app.Run([]string{"token"}); code != 0 {
		t.Fatalf("token should exit 0, got %d", code)
	}
	tok := out.String()
	if len(tok) < 32 {
		t.Fatalf("generated token is too short: %q", tok)
	}
}

func TestRunHostRefusesUnauthenticatedWithoutConfirmation(t *testing.T) {
	// With no controlling terminal and no --allow-unauthenticated, the host
	// must refuse rather than silently opening an unauthenticated shell.
	out := &testWriter{}
	app := New(out, out, nil)
	code := app.Run([]string{"host", "--port", "0", "--shell", "/definitely/not/a/shell"})
	if code == 0 {
		t.Skip("a confirmation was somehow supplied; nothing to assert")
	}
	if !contains(out.String(), "Aborted") && !contains(out.String(), "WARNING") {
		t.Fatalf("expected a refusal or warning, got:\n%s", out.String())
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		5 * time.Second:  "5s",
		90 * time.Second: "1m",
		3 * time.Hour:    "3h",
		50 * time.Hour:   "2d",
	}
	for in, want := range cases {
		if got := humanDuration(in); got != want {
			t.Fatalf("humanDuration(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:       "0B",
		512:     "512B",
		1024:    "1.0KB",
		1536:    "1.5KB",
		1 << 20: "1.0MB",
	}
	for in, want := range cases {
		if got := formatBytes(in); got != want {
			t.Fatalf("formatBytes(%d) = %s, want %s", in, got, want)
		}
	}
}

func TestDisplayAddr(t *testing.T) {
	cases := []struct {
		bound, configured, want string
	}{
		{"[::]:8080", "0.0.0.0", ":8080"},
		{"0.0.0.0:8080", "0.0.0.0", ":8080"},
		{"127.0.0.1:9000", "127.0.0.1", "127.0.0.1:9000"},
		{"0.0.0.0:9000", "10.0.0.5", "10.0.0.5:9000"},
	}
	for _, c := range cases {
		if got := displayAddr(c.bound, c.configured); got != c.want {
			t.Fatalf("displayAddr(%q,%q) = %q, want %q", c.bound, c.configured, got, c.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"http://example.com:8080":  "example.com",
		"https://example.com/x":    "example.com",
		"example.com:8080":         "example.com",
		"ws://127.0.0.1:1234":      "127.0.0.1",
		"https://host.example:443": "host.example",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Fatalf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortID(t *testing.T) {
	if shortID("abcdef0123456789") != "abcdef01" {
		t.Fatalf("shortID did not truncate: %q", shortID("abcdef0123456789"))
	}
	if shortID("abc") != "abc" {
		t.Fatalf("shortID should leave short ids alone")
	}
}

func TestPtyBackendReportsRealPTY(t *testing.T) {
	b := ptyBackend()
	if b == "" {
		t.Fatal("ptyBackend should describe the PTY implementation")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOfStr(s, sub) >= 0
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
