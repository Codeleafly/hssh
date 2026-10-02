package tunnel

import (
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := map[string]Provider{
		"":             ProviderLocal,
		"local":        ProviderLocal,
		"none":         ProviderLocal,
		"cloudflare":   ProviderCloudflare,
		"cf":           ProviderCloudflare,
		"ngrok":        ProviderNgrok,
		"localtunnel":  ProviderLocalTunnel,
		"lt":           ProviderLocalTunnel,
		"bore":         ProviderBore,
		"zrok":         ProviderZrok,
		"CloudFlare":   ProviderCloudflare,
		" NGROK ":      ProviderNgrok,
	}
	for in, want := range cases {
		got, err := Resolve(in)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("Resolve(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := Resolve("magic"); err == nil {
		t.Fatal("unknown provider should be an error")
	}
}

func TestNeedsTokenOnlyNgrok(t *testing.T) {
	if !NeedsToken(ProviderNgrok) {
		t.Fatal("ngrok must need a token")
	}
	for _, p := range []Provider{ProviderLocal, ProviderCloudflare, ProviderLocalTunnel, ProviderBore, ProviderZrok} {
		if NeedsToken(p) {
			t.Fatalf("%s should not require a token", p)
		}
	}
}

func TestTokenFromEnvPrecedence(t *testing.T) {
	t.Setenv("HSSH_TUNNEL_TOKEN", "generic")
	t.Setenv("NGROK_AUTHTOKEN", "ngrok-specific")
	t.Setenv("HSSH_NGROK_TOKEN", "hssh-specific")
	if got := TokenFromEnv(ProviderNgrok); got != "generic" {
		t.Fatalf("HSSH_TUNNEL_TOKEN should win, got %q", got)
	}
}

func TestCommandFor(t *testing.T) {
	cf, err := CommandFor(ProviderCloudflare, 8080, "")
	if err != nil || !strings.Contains(strings.Join(cf, " "), "8080") {
		t.Fatalf("cloudflare cmd = %v, %v", cf, err)
	}
	ng, _ := CommandFor(ProviderNgrok, 8080, "tok")
	if !strings.Contains(strings.Join(ng, " "), "tok") {
		t.Fatalf("ngrok cmd should carry token: %v", ng)
	}
	ng2, _ := CommandFor(ProviderNgrok, 8080, "")
	for _, a := range ng2 {
		if a == "tok" {
			t.Fatal("empty token must not appear")
		}
	}
	if _, err := CommandFor(ProviderLocal, 8080, ""); err == nil {
		t.Fatal("local should not build a command")
	}
	if _, err := CommandFor(ProviderBore, 0, ""); err == nil {
		t.Fatal("port 0 should fail")
	}
}

func TestParsePublicURL(t *testing.T) {
	cases := []struct {
		p    Provider
		out  string
		want string
	}{
		{ProviderCloudflare, "https://random-123.trycloudflare.com ready", "https://random-123.trycloudflare.com"},
		{ProviderNgrok, `{"URL":"https://abcd-123.ngrok-free.app"}`, "https://abcd-123.ngrok-free.app"},
		{ProviderLocalTunnel, "your url is: https://tidy-dog-12.loca.lt", "https://tidy-dog-12.loca.lt"},
		{ProviderBore, "listening at bore.pub:5234", "http://bore.pub:5234"},
		{ProviderZrok, "https://abc123.zrok.io", "https://abc123.zrok.io"},
	}
	for _, c := range cases {
		got, ok := ParsePublicURL(c.p, c.out)
		if !ok || got != c.want {
			t.Fatalf("%s: got %q,%v want %q", c.p, got, ok, c.want)
		}
	}
	if _, ok := ParsePublicURL(ProviderNgrok, "no url here"); ok {
		t.Fatal("garbage must not parse")
	}
	if _, ok := ParsePublicURL(ProviderLocalTunnel, "https://127.0.0.1:8080"); ok {
		t.Fatal("localhost must not count as public URL")
	}
	// Regression: cloudflared prints its ToS link on every start.
	// That is not a tunnel URL and must be ignored while waiting.
	if _, ok := ParsePublicURL(ProviderCloudflare, "https://www.cloudflare.com/website-terms/ ready"); ok {
		t.Fatal("cloudflare ToS link must not count as public URL")
	}
	if _, ok := ParsePublicURL(ProviderCloudflare, "no url here"); ok {
		t.Fatal("garbage must not parse for cloudflare")
	}
}

func TestBinaryNameAndHints(t *testing.T) {
	for _, p := range All() {
		if p != ProviderLocal && BinaryName(p) == "" {
			t.Fatalf("%s has no binary", p)
		}
		if TokenEnvHint(p) == "" {
			t.Fatalf("%s has no env hint", p)
		}
	}
}
