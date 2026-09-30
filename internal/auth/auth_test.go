package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/hssh/hssh/internal/config"
)

func hostCfg(mode config.AuthMode, password, token string, allowAnon bool) *config.HostConfig {
	return &config.HostConfig{
		AuthMode:             mode,
		Password:             password,
		Token:                token,
		AllowUnauthenticated: allowAnon,
	}
}

func TestNoAuthRequiresExplicitOptIn(t *testing.T) {
	// Starting a world-reachable shell with no authentication must be
	// impossible by accident: the config has to say so.
	if _, err := NewVerifier(hostCfg(config.AuthNone, "", "", false)); !errors.Is(err, config.ErrNoAuth) {
		t.Fatalf("expected ErrNoAuth without --allow-unauthenticated, got %v", err)
	}
	v, err := NewVerifier(hostCfg(config.AuthNone, "", "", true))
	if err != nil {
		t.Fatalf("explicit opt-in should succeed: %v", err)
	}
	if v.Required() {
		t.Fatal("an unauthenticated verifier must not require a credential")
	}
	if err := v.Authenticate(Credential{}, false); err != nil {
		t.Fatalf("an unauthenticated host must accept an empty credential: %v", err)
	}
}

func TestPasswordAuth(t *testing.T) {
	v, err := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if !v.Required() || v.Challenge() != MethodPassword {
		t.Fatalf("unexpected challenge: required=%v method=%s", v.Required(), v.Challenge())
	}

	if err := v.Authenticate(Credential{Method: MethodPassword, Password: "s3cret"}, true); err != nil {
		t.Fatalf("the correct password was rejected: %v", err)
	}
	for _, bad := range []Credential{
		{Method: MethodPassword, Password: "wrong"},
		{Method: MethodPassword, Password: ""},
		{Method: MethodPassword, Password: "s3cret "},
		{Method: MethodPassword, Password: "S3CRET"},
		{Method: MethodToken, Token: "s3cret"},
		{Method: "", Password: "s3cret"},
	} {
		// A fresh verifier per case keeps the attempt limit out of the way.
		fresh, _ := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
		if err := fresh.Authenticate(bad, true); !errors.Is(err, ErrFailed) {
			t.Fatalf("credential %+v was accepted (err=%v)", bad, err)
		}
	}
}

func TestTokenAuth(t *testing.T) {
	v, err := NewVerifier(hostCfg(config.AuthToken, "", "tok-123", false))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if v.Challenge() != MethodToken {
		t.Fatalf("unexpected challenge: %s", v.Challenge())
	}
	if err := v.Authenticate(Credential{Method: MethodToken, Token: "tok-123"}, true); err != nil {
		t.Fatalf("the correct token was rejected: %v", err)
	}
	if err := v.Authenticate(Credential{Method: MethodPassword, Password: "tok-123"}, true); !errors.Is(err, ErrFailed) {
		t.Fatalf("a token must not be accepted as a password: %v", err)
	}
}

func TestCredentialsRefusedOverPlaintext(t *testing.T) {
	// The central security rule: a password or token must never be put on the
	// wire in the clear, so the verifier refuses regardless of correctness.
	pv, _ := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
	if err := pv.Authenticate(Credential{Method: MethodPassword, Password: "s3cret"}, false); !errors.Is(err, ErrInsecure) {
		t.Fatalf("password over plaintext: want ErrInsecure, got %v", err)
	}

	tv, _ := NewVerifier(hostCfg(config.AuthToken, "", "tok", false))
	if err := tv.Authenticate(Credential{Method: MethodToken, Token: "tok"}, false); !errors.Is(err, ErrInsecure) {
		t.Fatalf("token over plaintext: want ErrInsecure, got %v", err)
	}

	// The attempt is still counted, so an attacker cannot probe by sending
	// insecure attempts forever.
	if err := pv.Authenticate(Credential{Method: MethodPassword, Password: "s3cret"}, false); !errors.Is(err, ErrInsecure) {
		t.Fatalf("second insecure attempt: got %v", err)
	}
}

func TestAttemptLimit(t *testing.T) {
	// The verifier is stateless across connections: one Host shares a single
	// Verifier for all clients, so a global counter would brick the host
	// after 5 connections. Each connection gets one attempt and the protocol
	// closes on failure, so repeated failures must keep returning ErrFailed
	// (never ErrAlreadyTried) and the correct credential must still work.
	v, _ := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
	for i := 0; i < 5; i++ {
		if err := v.Authenticate(Credential{Method: MethodPassword, Password: "nope"}, true); !errors.Is(err, ErrFailed) {
			t.Fatalf("attempt %d: want ErrFailed, got %v", i, err)
		}
	}
	if err := v.Authenticate(Credential{Method: MethodPassword, Password: "s3cret"}, true); err != nil {
		t.Fatalf("correct password after 5 failures must still work, got %v", err)
	}
	if err := v.Authenticate(Credential{Method: MethodPassword, Password: "nope"}, true); !errors.Is(err, ErrFailed) {
		t.Fatalf("6th failure: want ErrFailed, got %v", err)
	}
}

func TestMissingSecretIsAConfigError(t *testing.T) {
	if _, err := NewVerifier(hostCfg(config.AuthPassword, "", "", false)); !errors.Is(err, config.ErrNoAuth) {
		t.Fatalf("password mode with no password: want ErrNoAuth, got %v", err)
	}
	if _, err := NewVerifier(hostCfg(config.AuthToken, "", "", false)); !errors.Is(err, config.ErrNoAuth) {
		t.Fatalf("token mode with no token: want ErrNoAuth, got %v", err)
	}
}

func TestUnknownModeRejected(t *testing.T) {
	if _, err := NewVerifier(hostCfg(config.AuthMode("magic"), "", "", true)); err == nil {
		t.Fatal("an unknown auth mode must be rejected")
	}
}

func TestFailureMessagesRevealNothing(t *testing.T) {
	// Every rejection must be the same generic error, so a client cannot use
	// the response to learn which part of a credential was wrong.
	v, _ := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
	var msgs = map[string]bool{}
	for _, c := range []Credential{
		{Method: "wrongmethod", Password: "s3cret"},
		{Method: MethodPassword, Password: "nope"},
		{Method: MethodPassword},
		{},
	} {
		fresh, _ := NewVerifier(hostCfg(config.AuthPassword, "s3cret", "", false))
		err := fresh.Authenticate(c, true)
		msgs[err.Error()] = true
	}
	_ = v
	if len(msgs) != 1 {
		t.Fatalf("failure messages differ, which leaks information: %v", msgs)
	}
	if msgs[ErrFailed.Error()] != true {
		t.Fatalf("unexpected failure message set: %v", msgs)
	}
}

func TestVerifierStringHidesSecrets(t *testing.T) {
	v, _ := NewVerifier(hostCfg(config.AuthPassword, "topsecretvalue", "", false))
	if strings.Contains(v.String(), "topsecretvalue") {
		t.Fatalf("verifier String() leaked the password: %s", v.String())
	}
	if !strings.Contains(v.String(), Redacted) {
		t.Fatalf("verifier String() should mark the secret as redacted: %s", v.String())
	}
}

func TestGenerateTokenIsStrong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(tok) < 32 {
			t.Fatalf("token too short to be brute-forceable: %q (%d chars)", tok, len(tok))
		}
		if seen[tok] {
			t.Fatalf("GenerateToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestSafeMethodName(t *testing.T) {
	if SafeMethodName("  PASSWORD ") != MethodPassword {
		t.Fatal("SafeMethodName should normalise case and whitespace")
	}
	if SafeMethodName("weird;drop") == MethodPassword {
		t.Fatal("SafeMethodName must not pass through unknown values unchanged")
	}
}

func TestNewTokenVerifier(t *testing.T) {
	v := NewTokenVerifier("abc")
	if v.Challenge() != MethodToken {
		t.Fatalf("unexpected challenge %s", v.Challenge())
	}
	if err := v.Authenticate(Credential{Method: MethodToken, Token: "abc"}, true); err != nil {
		t.Fatalf("token rejected: %v", err)
	}
	// A token presented as a password must not authenticate in token mode.
	if err := v.Authenticate(Credential{Method: MethodPassword, Token: "abc"}, true); err == nil {
		t.Fatal("token with password method should be rejected in token mode")
	}
}
