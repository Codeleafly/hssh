// Package config parses HSSH command line and file configuration into validated
// settings. Nothing secret is ever stored in a Config's String output.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AuthMode selects the authentication strategy of a host.
type AuthMode string

const (
	AuthNone     AuthMode = "none"
	AuthPassword AuthMode = "password"
	AuthToken    AuthMode = "token"
)

// HostConfig is the validated configuration for `hssh host`.
type HostConfig struct {
	Host    string
	Port    int
	Shell   string
	WorkDir string

	AuthMode       AuthMode
	Password       string
	Token          string
	AllowAnonymous bool

	TLSCert string
	TLSKey  string

	MaxSessions  int
	MaxFrameSize int
	OutputBuffer int

	IdleTimeout    time.Duration
	SessionTimeout time.Duration
	Heartbeat      time.Duration
	ShutdownGrace  time.Duration

	LogLevel  string
	LogFormat string

	// PerSessionCwd isolates every session into its own scratch directory.
	PerSessionCwd bool

	// AllowUnauthenticated is the explicit opt-in that suppresses the
	// interactive "are you sure" prompt.
	AllowUnauthenticated bool

	// AllowResume lets a client reattach to a live session with --session=<id>.
	// Even then a session id is not a credential: the reconnecting client must
	// come from the same address and pass the same authentication.
	AllowResume bool

	// Public selects the tunnel backend for a public URL. Empty/local means
	// serve on --host/--port only (the default). See internal/tunnel.
	Public string
	// TunnelToken is the API token for providers that need one (ngrok).
	// Never logged; flag > HSSH_TUNNEL_TOKEN env > file.
	TunnelToken string

	// configFile records where the settings came from, for diagnostics.
	configFile string
}

// TLSEnabled reports whether HTTPS/WSS will be served.
func (c *HostConfig) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// Addr is the listen address.
func (c *HostConfig) Addr() string { return c.Host + ":" + strconv.Itoa(c.Port) }

// Secure reports whether credentials would travel over an encrypted channel.
func (c *HostConfig) Secure() bool { return c.TLSEnabled() }

// Redacted renders the config for logs: no password, no token, no key path.
func (c *HostConfig) Redacted() string {
	return fmt.Sprintf("addr=%s auth=%s tls=%t max_sessions=%d shell=%s",
		c.Addr(), c.AuthMode, c.TLSEnabled(), c.MaxSessions, c.shellOrAuto())
}

func (c *HostConfig) shellOrAuto() string {
	if c.Shell == "" {
		return "auto"
	}
	return c.Shell
}

// ClientConfig is the validated configuration for `hssh connect`.
type ClientConfig struct {
	URL           string
	Host          string
	Port          int
	TLS           bool
	AuthMode      AuthMode
	Password      string
	Token         string
	ResumeSession string
	// Cwd requests the directory the remote shell starts in. It is a path
	// on the SERVER, resolved against the host's working directory when
	// relative. Empty means the host default (its --workdir, else home).
	Cwd string

	Insecure   bool
	CAFile     string
	Disconnect []string
	Columns    int
	Rows       int
	LogLevel   string
	Timeout    time.Duration
}

// Validation errors.
var (
	ErrNoAuth       = errors.New("no authentication configured")
	ErrPortRange    = errors.New("port must be between 1 and 65535")
	ErrTLSPair      = errors.New("--tls-cert and --tls-key must be provided together")
	ErrTLSPairFiles = errors.New("TLS certificate or key file not found")
)

// Validate checks internal consistency and normalises defaults.
func (c *HostConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return ErrPortRange
	}
	if c.TLSCert == "" != (c.TLSKey == "") {
		return ErrTLSPair
	}
	if c.TLSEnabled() {
		for _, p := range []string{c.TLSCert, c.TLSKey} {
			if _, err := os.Stat(p); err != nil {
				return fmt.Errorf("%w: %s", ErrTLSPairFiles, p)
			}
		}
	}
	switch c.AuthMode {
	case AuthNone, AuthPassword, AuthToken:
	default:
		return fmt.Errorf("unknown auth mode %q", c.AuthMode)
	}
	if c.AuthMode == AuthNone && (c.Password != "" || c.Token != "") {
		// Credentials supplied but auth mode not set: infer it.
		if c.Password != "" {
			c.AuthMode = AuthPassword
		} else {
			c.AuthMode = AuthToken
		}
	}
	if c.MaxSessions < 0 {
		return errors.New("--max-sessions must be positive")
	}
	if c.IdleTimeout < 0 {
		return errors.New("--idle-timeout must not be negative")
	}
	if c.SessionTimeout < 0 {
		return errors.New("--session-timeout must not be negative")
	}
	if c.Heartbeat < 0 {
		return errors.New("--heartbeat must not be negative")
	}
	if c.OutputBuffer > 256<<20 {
		return errors.New("--output-buffer is unreasonably large (max 256M)")
	}
	if c.MaxFrameSize < 1024 {
		c.MaxFrameSize = 1 << 20 // 1 MiB, matches wsx.DefaultLimits
	}
	if c.OutputBuffer < 4096 {
		c.OutputBuffer = 4 << 20 // 4 MiB, matches terminal.DefaultPumpConfig
	}
	return nil
}

// LoadHostFile merges a JSON config file (if HSSH_CONFIG, ./hssh.json,
// ~/.hssh/host.json, ~/.hssh/config.json or ~/.config/hssh/host.json exists)
// under the command line flags. Flags always win.
func LoadHostFile(flags *HostConfig) (*HostConfig, error) {
	path := os.Getenv("HSSH_CONFIG")
	if path == "" {
		cands := append([]string{"hssh.json"}, ConfigCandidates()...)
		for _, cand := range cands {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				path = cand
				break
			}
		}
	}
	out := *flags
	if path == "" {
		return &out, nil
	}
	if err := mergeJSONFile(path, &out); err != nil {
		return nil, err
	}
	out.configFile = path
	return &out, nil
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

// sizeSuffixes maps a unit suffix to its multiplier. The longest match wins,
// so "MiB" is not mistaken for "B" and "MIB" is not mistaken for "I".
var sizeSuffixes = []struct {
	suffix string
	mult   int
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
	{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
	{"B", 1},
}

// ParseSize accepts 4096, 512K, 2M, 4MiB, 1GiB. Matching is
// case-insensitive.
func ParseSize(in string) (int, error) {
	s := strings.ToUpper(strings.TrimSpace(in))
	if s == "" {
		return 0, errors.New("empty size")
	}
	mult := 1
	for _, u := range sizeSuffixes {
		if u.suffix == "B" {
			continue
		}
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = s[:len(s)-len(u.suffix)]
			break
		}
	}
	if strings.HasSuffix(s, "B") {
		s = s[:len(s)-1]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", strings.TrimSpace(in))
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q", strings.TrimSpace(in))
	}
	return n * mult, nil
}

// ParseDuration accepts 30s, 5m, 2h, 1h30m, or a bare number of seconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return time.Duration(n) * time.Second, nil
}
