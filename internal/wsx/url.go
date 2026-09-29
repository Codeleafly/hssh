package wsx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// ProtocolSubprotocol is negotiated during the Upgrade so a plain WebSocket
// client cannot accidentally attach to an HSSH host.
const ProtocolSubprotocol = "hssh.v1"

// ClientTLS is a client TLS configuration. It is exported so callers outside
// this package (including tests with a self-signed certificate) can supply
// their own trust roots instead of only using BuildTLS.
type ClientTLS struct{ cfg *tls.Config }

// WrapClientTLS exposes an externally built *tls.Config.
func WrapClientTLS(cfg *tls.Config) *ClientTLS { return &ClientTLS{cfg: cfg} }

// Config returns the wrapped configuration.
func (t *ClientTLS) Config() *tls.Config { return t.cfg }

// TLSOptions describes how the client verifies the server.
type TLSOptions struct {
	// CAFile is a PEM bundle of trusted CAs; nil uses the system pool.
	CAFile string
	// InsecureSkipVerify is for lab use only and is loudly surfaced by the CLI.
	InsecureSkipVerify bool
	// ServerName overrides SNI/verification when connecting by IP.
	ServerName string
}

// BuildTLS turns options into a *tls.Config.
func BuildTLS(o TLSOptions) (*ClientTLS, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: o.InsecureSkipVerify, //nolint:gosec // explicit opt-in
		ServerName:         o.ServerName,
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", o.CAFile)
		}
		cfg.RootCAs = pool
	}
	return &ClientTLS{cfg: cfg}, nil
}

// parseWSURL validates a ws:// or wss:// URL.
func parseWSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("expected a ws:// or wss:// URL, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", raw)
	}
	return u, nil
}

// parseOriginURL parses an Origin header value. The "null" origin, produced by
// a sandboxed iframe, has no host and is refused.
func parseOriginURL(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("origin has no host")
	}
	return u, nil
}

// defaultPortForScheme maps a URL scheme to its IANA default port.
func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return "443"
	default:
		return "80"
	}
}

// equalAuthority compares two authority strings, tolerating case and an
// omitted default port, so "host", "host:80" and "HOST:80" all match when the
// default port is 80.
func equalAuthority(a, b, defaultPort string) bool {
	return normalizeAuthority(a, defaultPort) == normalizeAuthority(b, defaultPort)
}

// normalizeAuthority lowercases an authority and fills in the missing default
// port.
func normalizeAuthority(s, defaultPort string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return strings.ToLower(net.JoinHostPort(s, defaultPort))
	}
	if port == "" {
		port = defaultPort
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

// WellKnownEndpoint is the path a client upgrades on.
const WellKnownEndpoint = "/connect"

// HealthEndpoint reports server liveness and protocol version.
const HealthEndpoint = "/health"

// DefaultHandshakeTimeout is the time allowed for the whole HTTP+WS handshake.
const DefaultHandshakeTimeout = 15 * time.Second
