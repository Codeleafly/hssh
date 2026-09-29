package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/wsx"
)

// WebSocket close codes the client uses.
const (
	wsxCloseNormal   = 1000
	wsxCloseAbnormal = 1006
	wsxClosePolicy   = 1008
	wsxCloseInternal = 1011
)

type x509CertError = x509.UnknownAuthorityError

// newHealthRequest builds the discovery request for an http(s) target.
func newHealthRequest(target string) (*http.Request, error) {
	base, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	base.Path = wsx.HealthEndpoint
	base.RawQuery = ""
	return http.NewRequest(http.MethodGet, base.String(), nil)
}

// parseTarget normalises a user-supplied target into an *url.URL, accepting
// hssh:// as an alias for http:// and filling in the default port.
func parseTarget(target string) (*url.URL, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("no server address given")
	}
	// Accept the paste-friendly forms users actually type.
	switch {
	case strings.HasPrefix(t, "hssh://"):
		t = "http://" + strings.TrimPrefix(t, "hssh://")
	case strings.HasPrefix(t, "localhost:"), strings.HasPrefix(t, "127.0.0.1:"),
		strings.HasPrefix(t, "[::1]:"):
		if !strings.Contains(t, "://") {
			t = "http://" + t
		}
	case !strings.Contains(t, "://"):
		t = "http://" + t
	}

	u, err := url.Parse(t)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", target, err)
	}
	switch u.Scheme {
	case "http", "https":
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, fmt.Errorf("unsupported scheme %q (use http, https, ws or wss)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("address %q has no host", target)
	}
	if u.Port() == "" {
		if u.Scheme == "https" {
			u.Host = u.Host + ":443"
		} else {
			u.Host = u.Host + ":8080"
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// toWSURL maps an http(s) URL to the ws(s) URL of the connect endpoint.
func toWSURL(target string) string {
	u, err := parseTarget(target)
	if err != nil {
		return target
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	u.Path = wsx.WellKnownEndpoint
	return u.String()
}

// httpClient builds an HTTP client honouring the TLS options.
func httpClient(cfg *config.ClientConfig) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if cfg.TLS {
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // explicit opt-in
			ServerName:         cfg.Host,
		}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(pem) {
					tlsCfg.RootCAs = pool
				}
			}
		}
		tr.TLSClientConfig = tlsCfg
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func doRequest(req *http.Request, cfg *config.ClientConfig) (*http.Response, []byte, error) {
	req.Header.Set("User-Agent", "hssh/"+versionString)
	resp, err := httpClient(cfg).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return resp, nil, err
	}
	return resp, body, nil
}

func decodeJSON(b []byte, v any) error { return json.Unmarshal(b, v) }

// termValue picks the TERM to request. Advertising the local TERM keeps colour
// and character-set expectations aligned with the client's terminal.
func (c *Client) termValue() string {
	if v := os.Getenv("TERM"); v != "" && v != "dumb" {
		return v
	}
	switch runtime.GOOS {
	case "windows":
		return "xterm-256color"
	default:
		return "xterm-256color"
	}
}

// colorScheme hints whether the client terminal has a dark background, which
// some shells use to pick sensible default colours.
func (c *Client) colorScheme() string {
	switch os.Getenv("COLORFGBG") {
	case "":
		return "unknown"
	default:
		fg := os.Getenv("COLORFGBG")
		if len(fg) >= 7 && fg[len(fg)-7:len(fg)-6] == "6" {
			return "light"
		}
		return "dark"
	}
}

var versionString = "1.0.0"

func nowMillis() int64 { return time.Now().UnixMilli() }
