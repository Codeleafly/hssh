package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func base() *HostConfig {
	return &HostConfig{
		Host:                 "127.0.0.1",
		Port:                 8080,
		AuthMode:             AuthNone,
		AllowUnauthenticated: true,
		OutputBuffer:         1 << 20,
		MaxFrameSize:         1 << 20,
	}
}

func TestValidateRejectsBadPort(t *testing.T) {
	for _, p := range []int{0, -1, 70000} {
		c := base()
		c.Port = p
		if err := c.Validate(); !errors.Is(err, ErrPortRange) {
			t.Fatalf("port %d should be rejected, got %v", p, err)
		}
	}
	for _, p := range []int{1, 80, 8080, 65535} {
		c := base()
		c.Port = p
		if err := c.Validate(); err != nil {
			t.Fatalf("port %d should be accepted: %v", p, err)
		}
	}
}

func TestValidateRequiresTLSKeyPair(t *testing.T) {
	c := base()
	c.TLSCert = "cert.pem"
	if err := c.Validate(); !errors.Is(err, ErrTLSPair) {
		t.Fatalf("cert without key should fail, got %v", err)
	}
	c = base()
	c.TLSKey = "key.pem"
	if err := c.Validate(); !errors.Is(err, ErrTLSPair) {
		t.Fatalf("key without cert should fail, got %v", err)
	}
}

func TestValidateChecksTLSFilesExist(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := base()
	c.TLSCert, c.TLSKey = cert, key
	if err := c.Validate(); err != nil {
		t.Fatalf("existing key pair should validate: %v", err)
	}
	if !c.TLSEnabled() {
		t.Fatal("TLSEnabled should be true")
	}

	c.TLSCert = filepath.Join(dir, "missing.pem")
	if err := c.Validate(); !errors.Is(err, ErrTLSPairFiles) {
		t.Fatalf("missing cert file should fail, got %v", err)
	}
}

func TestValidateInfersAuthModeFromCredentials(t *testing.T) {
	// Supplying a password without --auth must not silently leave the host
	// unauthenticated.
	c := base()
	c.Password = "hunter2"
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.AuthMode != AuthPassword {
		t.Fatalf("auth mode should have been inferred as password, got %q", c.AuthMode)
	}

	c = base()
	c.Token = "tok"
	_ = c.Validate()
	if c.AuthMode != AuthToken {
		t.Fatalf("auth mode should have been inferred as token, got %q", c.AuthMode)
	}
}

func TestValidateRejectsUnknownAuthMode(t *testing.T) {
	c := base()
	c.AuthMode = AuthMode("magic")
	if err := c.Validate(); err == nil {
		t.Fatal("an unknown auth mode must be rejected")
	}
}

func TestValidateNormalisesBufferLimits(t *testing.T) {
	c := base()
	c.MaxFrameSize = 10
	c.OutputBuffer = 10
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.MaxFrameSize < 1024 {
		t.Fatalf("frame size should be raised to a sane floor, got %d", c.MaxFrameSize)
	}
	if c.OutputBuffer < 4096 {
		t.Fatalf("output buffer should be raised to a sane floor, got %d", c.OutputBuffer)
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	c := base()
	c.Password = "supersecretpassword"
	c.Token = "supersecrettoken"
	out := c.Redacted()
	if contains(out, "supersecret") {
		t.Fatalf("Redacted leaked a secret: %s", out)
	}
	if !contains(out, "auth=none") {
		t.Fatalf("Redacted should describe the auth mode: %s", out)
	}
}

func TestAddr(t *testing.T) {
	c := base()
	if got := c.Addr(); got != "127.0.0.1:8080" {
		t.Fatalf("Addr() = %q", got)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int{
		"1024": 1024,
		"1K":   1 << 10,
		"1KB":  1 << 10,
		"1KiB": 1 << 10,
		"2M":   2 << 20,
		"4MiB": 4 << 20,
		"1G":   1 << 30,
		"8K":   8 << 10,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil {
			t.Fatalf("ParseSize(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "1X", "-5"} {
		if _, err := ParseSize(bad); err == nil {
			t.Fatalf("ParseSize(%q) should fail", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"30s":   30 * time.Second,
		"5m":    5 * time.Minute,
		"2h":    2 * time.Hour,
		"45":    45 * time.Second,
		"1h30m": 90 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseDuration(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "5x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Fatalf("ParseDuration(%q) should fail", bad)
		}
	}
}

func TestLoadHostFileFromJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	body := `{
	  "host": "10.0.0.5",
	  "port": 9999,
	  "shell": "zsh",
	  "password": "fromfile",
	  "max_sessions": 3,
	  "idle_timeout": "15m",
	  "per_session_cwd": true
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HSSH_CONFIG", path)

	flags := &HostConfig{Host: "0.0.0.0", Port: 8080, OutputBuffer: 1 << 20, MaxFrameSize: 1 << 20}
	got, err := LoadHostFile(flags)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Host != "10.0.0.5" || got.Port != 9999 || got.Shell != "zsh" {
		t.Fatalf("file values not applied: %+v", got)
	}
	if got.Password != "fromfile" {
		t.Fatalf("password not read from file")
	}
	if got.MaxSessions != 3 {
		t.Fatalf("max_sessions = %d", got.MaxSessions)
	}
	if got.IdleTimeout != 15*time.Minute {
		t.Fatalf("idle_timeout = %s", got.IdleTimeout)
	}
	if !got.PerSessionCwd {
		t.Fatal("per_session_cwd not applied")
	}
}

func TestLoadHostFileRejectsBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HSSH_CONFIG", path)
	if _, err := LoadHostFile(&HostConfig{}); err == nil {
		t.Fatal("malformed JSON should be reported, not ignored")
	}
}

func TestLoadHostFileRejectsBadDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	if err := os.WriteFile(path, []byte(`{"idle_timeout":"soon"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HSSH_CONFIG", path)
	if _, err := LoadHostFile(&HostConfig{}); err == nil {
		t.Fatal("an unparsable duration should be reported")
	}
}

func TestLoadHostFileExplicitMissingFileIsAnError(t *testing.T) {
	// If the operator names a config file, silently ignoring it would run the
	// host with settings they did not intend.
	t.Setenv("HSSH_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := LoadHostFile(&HostConfig{}); err == nil {
		t.Fatal("an explicitly requested config file that is missing must be reported")
	}
}

func TestLoadHostFileNoFileIsFine(t *testing.T) {
	// No HSSH_CONFIG and nothing discoverable: the flags are used as-is.
	t.Setenv("HSSH_CONFIG", "")
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	got, err := LoadHostFile(&HostConfig{Host: "1.2.3.4", Port: 1})
	if err != nil {
		t.Fatalf("no config file should not be an error: %v", err)
	}
	if got.Host != "1.2.3.4" || got.Port != 1 {
		t.Fatalf("flags were lost: %+v", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
