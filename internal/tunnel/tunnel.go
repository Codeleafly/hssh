// Package tunnel exposes an HSSH host on a public URL.
//
// Modes:
//
//	local (default) — no tunnel, serve on --host/--port only.
//	cloudflare      — `cloudflared tunnel --url http://127.0.0.1:PORT`
//	ngrok           — `ngrok http PORT` (+ token when set)
//	localtunnel     — `npx -y localtunnel --port PORT`
//	bore            — `bore local PORT --to bore.pub`
//	zrok            — `zrok share public http://127.0.0.1:PORT`
//
// Tokens are never logged. Resolution order for a token is:
// --tunnel-token flag > HSSH_TUNNEL_TOKEN > provider env
// (NGROK_AUTHTOKEN/HSSH_NGROK_TOKEN, CLOUDFLARE_API_TOKEN/HSSH_CLOUDFLARE_TOKEN,
// ZROK_TOKEN/HSSH_ZROK_TOKEN). Providers that need no API (localtunnel, bore)
// ignore tokens. Default is always local, even when env vars are set.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Provider is a public-exposure backend.
type Provider string

const (
	ProviderLocal       Provider = "local"
	ProviderCloudflare  Provider = "cloudflare"
	ProviderNgrok       Provider = "ngrok"
	ProviderLocalTunnel Provider = "localtunnel"
	ProviderBore        Provider = "bore"
	ProviderZrok        Provider = "zrok"
)

// All lists every accepted value (canonical names).
func All() []Provider {
	return []Provider{
		ProviderLocal,
		ProviderCloudflare,
		ProviderNgrok,
		ProviderLocalTunnel,
		ProviderBore,
		ProviderZrok,
	}
}

// Resolve maps a user value to a Provider. Empty means local (the default).
// Aliases: cf→cloudflare, lt→localtunnel, ""→local.
func Resolve(s string) (Provider, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "", "local", "none", "off", "false":
		return ProviderLocal, nil
	case "cloudflare", "cf", "cloudflared", "trycloudflare":
		return ProviderCloudflare, nil
	case "ngrok":
		return ProviderNgrok, nil
	case "localtunnel", "lt", "local-tunnel", "local tunnel":
		return ProviderLocalTunnel, nil
	case "bore":
		return ProviderBore, nil
	case "zrok":
		return ProviderZrok, nil
	}
	return "", fmt.Errorf("tunnel: unknown provider %q (want %s)", s, strings.Join(Names(), ", "))
}

// Names returns canonical provider names for help text.
func Names() []string {
	out := make([]string, 0, len(All()))
	for _, p := range All() {
		out = append(out, string(p))
	}
	return out
}

// NeedsToken reports whether the provider requires an API token to start.
func NeedsToken(p Provider) bool {
	return p == ProviderNgrok
}

// TokenFromEnv returns the API token for a provider from the environment.
// HSSH_TUNNEL_TOKEN overrides every provider-specific variable.
func TokenFromEnv(p Provider) string {
	if v := strings.TrimSpace(os.Getenv("HSSH_TUNNEL_TOKEN")); v != "" {
		return v
	}
	switch p {
	case ProviderNgrok:
		if v := strings.TrimSpace(os.Getenv("HSSH_NGROK_TOKEN")); v != "" {
			return v
		}
		return strings.TrimSpace(os.Getenv("NGROK_AUTHTOKEN"))
	case ProviderCloudflare:
		if v := strings.TrimSpace(os.Getenv("HSSH_CLOUDFLARE_TOKEN")); v != "" {
			return v
		}
		if v := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")); v != "" {
			return v
		}
		return strings.TrimSpace(os.Getenv("TUNNEL_TOKEN"))
	case ProviderZrok:
		if v := strings.TrimSpace(os.Getenv("HSSH_ZROK_TOKEN")); v != "" {
			return v
		}
		return strings.TrimSpace(os.Getenv("ZROK_TOKEN"))
	}
	return ""
}

// TokenEnvHint names the env vars consulted for a provider (for errors/help).
func TokenEnvHint(p Provider) string {
	switch p {
	case ProviderNgrok:
		return "HSSH_TUNNEL_TOKEN or HSSH_NGROK_TOKEN or NGROK_AUTHTOKEN"
	case ProviderCloudflare:
		return "HSSH_TUNNEL_TOKEN or HSSH_CLOUDFLARE_TOKEN or CLOUDFLARE_API_TOKEN (optional for quick tunnels)"
	case ProviderZrok:
		return "HSSH_TUNNEL_TOKEN or HSSH_ZROK_TOKEN or ZROK_TOKEN (only for private shares)"
	default:
		return "no API token needed"
	}
}

// BinaryName is the executable expected on PATH for a provider.
func BinaryName(p Provider) string {
	switch p {
	case ProviderCloudflare:
		return "cloudflared"
	case ProviderNgrok:
		return "ngrok"
	case ProviderLocalTunnel:
		return "npx"
	case ProviderBore:
		return "bore"
	case ProviderZrok:
		return "zrok"
	}
	return ""
}

// InstallHint tells the user how to get the provider binary.
func InstallHint(p Provider) string {
	switch p {
	case ProviderCloudflare:
		return "install cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
	case ProviderNgrok:
		return "install ngrok: https://ngrok.com/download + set NGROK_AUTHTOKEN"
	case ProviderLocalTunnel:
		return "needs node: npx -y localtunnel (npm i -g localtunnel)"
	case ProviderBore:
		return "install bore: cargo install bore-cli (https://github.com/ekzhang/bore)"
	case ProviderZrok:
		return "install zrok: https://docs.zrok.io/docs/guides/install/"
	}
	return ""
}

// CommandFor builds the tunnel command for a provider (pure, testable).
// port is the already-bound local HSSH port.
func CommandFor(p Provider, port int, token string) ([]string, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("tunnel: invalid port %d", port)
	}
	local := fmt.Sprintf("http://127.0.0.1:%d", port)
	switch p {
	case ProviderLocal:
		return nil, errors.New("tunnel: local provider needs no command")
	case ProviderCloudflare:
		return []string{"cloudflared", "tunnel", "--url", local}, nil
	case ProviderNgrok:
		args := []string{"ngrok", "http", fmt.Sprint(port), "--log", "stdout", "--log-format", "json"}
		if token != "" {
			args = append(args, "--authtoken", token)
		}
		return args, nil
	case ProviderLocalTunnel:
		return []string{"npx", "-y", "localtunnel", "--port", fmt.Sprint(port)}, nil
	case ProviderBore:
		return []string{"bore", "local", fmt.Sprint(port), "--to", "bore.pub"}, nil
	case ProviderZrok:
		return []string{"zrok", "share", "public", local}, nil
	}
	return nil, fmt.Errorf("tunnel: unknown provider %q", p)
}

var (
	reCloudflare  = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)
	reNgrok       = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)`)
	reLocalTunnel = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.loca\.lt`)
	reZrok        = regexp.MustCompile(`https://[a-zA-Z0-9.-]+\.zrok\.io`)
	reBore        = regexp.MustCompile(`bore\.pub:\d+`)
	reAnyHTTPS    = regexp.MustCompile(`https://[^\s"']+`)
)

// ParsePublicURL extracts the public URL from tunnel process output (pure,
// testable). ok=false means "no URL yet, keep reading".
func ParsePublicURL(p Provider, output string) (url string, ok bool) {
	switch p {
	case ProviderCloudflare:
		if m := reCloudflare.FindString(output); m != "" {
			return m, true
		}
	case ProviderNgrok:
		if m := reNgrok.FindString(output); m != "" {
			return m, true
		}
	case ProviderLocalTunnel:
		if m := reLocalTunnel.FindString(output); m != "" {
			return m, true
		}
	case ProviderBore:
		if m := reBore.FindString(output); m != "" {
			return "http://" + m, true
		}
	case ProviderZrok:
		if m := reZrok.FindString(output); m != "" {
			return m, true
		}
	}
	// Generic fallback for providers whose exact host pattern changed:
	// accept any https URL except localhost/127.0.0.1 and vendor docs pages
	// (cloudflared prints https://www.cloudflare.com/website-terms/ on every
	// start — that is not a tunnel URL and must never be accepted).
	if m := reAnyHTTPS.FindString(output); m != "" {
		if !strings.Contains(m, "127.0.0.1") && !strings.Contains(m, "localhost") &&
			!strings.Contains(m, "cloudflare.com/") && !strings.Contains(m, "ngrok.com/") {
			// Only use the fallback for providers that serve HTTPS.
			// Cloudflare is excluded: only *.trycloudflare.com is valid,
			// the fallback already caused a website-terms false positive.
			if p == ProviderNgrok ||
				p == ProviderLocalTunnel || p == ProviderZrok {
				return strings.TrimRight(m, ".,;)"), true
			}
		}
	}
	return "", false
}

// Tunnel is a running public tunnel process.
type Tunnel struct {
	provider Provider
	url      string
	cmd      *exec.Cmd
	mu       sync.Mutex
	closed   bool
}

// Provider returns the backend.
func (t *Tunnel) Provider() Provider { return t.provider }

// URL is the public URL clients should use (https://… or http://bore.pub:port).
func (t *Tunnel) URL() string { return t.url }

// Close stops the tunnel process.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		_, _ = t.cmd.Process.Wait()
	}
	return nil
}

// Options configures Start.
type Options struct {
	Provider Provider
	Port     int
	// Token overrides env (flag wins). Empty means "read from env".
	Token string
	// Wait caps how long to wait for the public URL. <=0 means 30s.
	Wait time.Duration
}

// Start launches the provider binary and waits until its public URL appears.
func Start(ctx context.Context, o Options) (*Tunnel, error) {
	if o.Provider == "" || o.Provider == ProviderLocal {
		return nil, errors.New("tunnel: local provider needs no tunnel")
	}
	token := o.Token
	if token == "" {
		token = TokenFromEnv(o.Provider)
	}
	if NeedsToken(o.Provider) && token == "" {
		return nil, fmt.Errorf("tunnel: %s needs an API token: set %s", o.Provider, TokenEnvHint(o.Provider))
	}
	argv, err := CommandFor(o.Provider, o.Port, token)
	if err != nil {
		return nil, err
	}
	bin := argv[0]
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("tunnel: %s not found on PATH (%s): %s", bin, BinaryName(o.Provider), InstallHint(o.Provider))
	}
	wait := o.Wait
	if wait <= 0 {
		wait = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Tokens must never appear in logs: pass via args only to the child.
	// (ngrok --authtoken is the documented way; process list exposure is
	// accepted upstream and matches `ngrok config add-authtoken` behaviour.)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tunnel: start %s: %w", bin, err)
	}

	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		var buf strings.Builder
		for sc.Scan() {
			buf.WriteString(sc.Text())
			buf.WriteByte('\n')
			if u, ok := ParsePublicURL(o.Provider, buf.String()); ok {
				select {
				case found <- u:
				default:
				}
				return
			}
		}
	}()

	select {
	case u := <-found:
		return &Tunnel{provider: o.Provider, url: u, cmd: cmd}, nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("tunnel: timed out waiting for %s public URL (is %s installed and reachable? %s)", o.Provider, BinaryName(o.Provider), InstallHint(o.Provider))
		}
		return nil, fmt.Errorf("tunnel: %s: %w", o.Provider, ctx.Err())
	}
}
