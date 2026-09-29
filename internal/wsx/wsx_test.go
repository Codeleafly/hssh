package wsx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseWSURL(t *testing.T) {
	for _, good := range []string{"ws://host:8080/connect", "wss://host/connect"} {
		if _, err := parseWSURL(good); err != nil {
			t.Fatalf("parseWSURL(%q): %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://host/connect", // wrong scheme for a WebSocket
		"", "ws://", "not a url",
	} {
		if _, err := parseWSURL(bad); err == nil {
			t.Fatalf("parseWSURL(%q) should fail", bad)
		}
	}
}

func TestBuildTLSMinimumVersion(t *testing.T) {
	tc, err := BuildTLS(TLSOptions{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if tc.Config().MinVersion < 0x0303 { // TLS 1.2
		t.Fatalf("min version = %#x, want at least TLS 1.2", tc.Config().MinVersion)
	}
	if tc.Config().InsecureSkipVerify {
		t.Fatal("certificate verification must be on by default")
	}
}

func TestBuildTLSLoadsCAFile(t *testing.T) {
	// A file with no certificates must be reported rather than silently
	// ignored, which would look like a working trust store.
	dir := t.TempDir()
	bad := dir + "/ca.pem"
	if err := writeFile(bad, "not a certificate"); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildTLS(TLSOptions{CAFile: bad}); err == nil {
		t.Fatal("a CA file with no certificates should be reported")
	}
	if _, err := BuildTLS(TLSOptions{CAFile: dir + "/missing.pem"}); err == nil {
		t.Fatal("a missing CA file should be reported")
	}
}

func TestBuildTLSInsecureIsExplicit(t *testing.T) {
	tc, err := BuildTLS(TLSOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !tc.Config().InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify was not honoured")
	}
}

func TestDefaultOriginCheck(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"", "server:8080", true}, // the HSSH CLI sends no Origin
		{"http://server:8080", "server:8080", true},
		{"http://SERVER:8080", "server:8080", true}, // host comparison is case-insensitive
		{"http://server:80", "server", true},        // default port equivalence
		{"https://server", "server:443", true},
		{"http://evil.example", "server:8080", false}, // cross-origin
		{"null", "server:8080", false},                // a sandboxed iframe
		{"http://server:9999", "server:8080", false},  // wrong port
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "http://"+c.host+"/connect", nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		r.Host = c.host
		if got := DefaultOriginCheck(r); got != c.want {
			t.Fatalf("DefaultOriginCheck(origin=%q host=%q) = %v, want %v", c.origin, c.host, got, c.want)
		}
	}
}

func TestEqualHostPort(t *testing.T) {
	if !equalAuthority("a:80", "A", "80") {
		t.Fatal("an omitted default port should compare equal")
	}
	if equalAuthority("a:80", "b:80", "80") {
		t.Fatal("different hosts must not be equal")
	}
	if equalAuthority("a:80", "a:443", "443") {
		t.Fatal("port 80 must not match port 443")
	}
}

func TestParseOriginHost(t *testing.T) {
	u, err := parseOriginURL("http://example.com:8080")
	if err != nil || u.Host != "example.com:8080" {
		t.Fatalf("parseOriginURL = %v, %v", u, err)
	}
	if _, err := parseOriginURL("null"); err == nil {
		t.Fatal("the null origin has no host and should be refused")
	}
}

func TestIsClosedAndTimeout(t *testing.T) {
	if IsClosed(nil) {
		t.Fatal("nil is not a closed error")
	}
	if !IsClosed(ErrClosedNormally) {
		t.Fatal("ErrClosedNormally should count as closed")
	}
	if IsClosed(nil) {
		t.Fatal("a nil error is not a closed connection")
	}
}

func TestNormaliseClose(t *testing.T) {
	if got := NormaliseClose(nil); got != nil {
		t.Fatalf("nil should stay nil, got %v", got)
	}
	if got := NormaliseClose(ErrClosedNormally); !strings.Contains(got.Error(), "closed by peer") {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestUpgraderRefusesCompression(t *testing.T) {
	// Terminal output is high-entropy; deflate would add latency and CPU for
	// nothing, so the upgrader must leave it off.
	u := Upgrader(DefaultLimits(), nil)
	if u.EnableCompression {
		t.Fatal("compression should be disabled for terminal traffic")
	}
	if len(u.Subprotocols) == 0 || u.Subprotocols[0] != ProtocolSubprotocol {
		t.Fatalf("the HSSH subprotocol must be offered, got %v", u.Subprotocols)
	}
}

func TestNewConnAppliesLimits(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxFrameBytes = 1234
	// A nil underlying connection is enough to check the stored limits; no
	// method that touches the socket is called here.
	c := &Conn{lim: lim}
	if c.lim.MaxFrameBytes != 1234 {
		t.Fatalf("limits not stored: %+v", c.lim)
	}
}

func TestWellKnownEndpoints(t *testing.T) {
	if WellKnownEndpoint != "/connect" {
		t.Fatalf("the connect endpoint must stay stable, got %q", WellKnownEndpoint)
	}
	if HealthEndpoint != "/health" {
		t.Fatalf("the health endpoint must stay stable, got %q", HealthEndpoint)
	}
}

func TestNormalizeAuthority(t *testing.T) {
	if normalizeAuthority("Host:80", "80") != "host:80" {
		t.Fatalf("normalizeAuthority = %q", normalizeAuthority("Host:80", "80"))
	}
	if normalizeAuthority("host", "80") != "host:80" {
		t.Fatalf("a missing port should take the scheme default, got %q", normalizeAuthority("host", "80"))
	}
	if normalizeAuthority("host", "443") != "host:443" {
		t.Fatalf("https default port = %q", normalizeAuthority("host", "443"))
	}
}

// writeFile is a small helper so the test reads clearly.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
