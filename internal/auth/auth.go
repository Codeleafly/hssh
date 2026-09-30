// Package auth implements HSSH's optional authentication.
//
// Two rules shape the design:
//
//  1. Credentials must never be written to a log. The Verifier only ever sees
//     a digest, and every error message is generic enough to be useless to an
//     attacker probing for valid credentials.
//  2. Plain HTTP is not an acceptable transport for a password or a token.
//     Authenticate() refuses to complete over an unencrypted connection unless
//     the operator has explicitly accepted the risk.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hssh/hssh/internal/config"
)

// Errors returned by the verifier. They are deliberately coarse.
var (
	ErrFailed   = errors.New("authentication failed")
	ErrRequired = errors.New("authentication required")
	ErrMethod   = errors.New("unsupported authentication method")
	ErrInsecure = errors.New("refusing to send credentials over an unencrypted connection")
	// ErrAlreadyTried is kept for compatibility but no longer returned:
	// the verifier is stateless across connections (see Authenticate).
	ErrAlreadyTried = errors.New("too many authentication attempts")
)

// Method names as they appear on the wire.
const (
	MethodNone     = "none"
	MethodPassword = "password"
	MethodToken    = "token"
)

// Credential is the material presented by a client. It is compared in constant
// time and then dropped; nothing keeps a plaintext copy.
type Credential struct {
	Method   string
	Password string
	Token    string
}

// Verifier decides whether a credential is acceptable.
type Verifier struct {
	mode config.AuthMode
	// Stored as digests so the plaintext never sits in long-lived heap memory
	// and cannot be dumped by accident.
	pwDigest  [32]byte
	tokDigest [32]byte
	hasPw     bool
	hasTok    bool

	anonymous bool
}

// NewVerifier builds a verifier from the host configuration.
func NewVerifier(cfg *config.HostConfig) (*Verifier, error) {
	v := &Verifier{mode: cfg.AuthMode, anonymous: true}
	switch cfg.AuthMode {
	case config.AuthPassword:
		if cfg.Password == "" {
			return nil, config.ErrNoAuth
		}
		v.pwDigest = sha256.Sum256([]byte(cfg.Password))
		v.hasPw = true
		v.anonymous = false
	case config.AuthToken:
		if cfg.Token == "" {
			return nil, config.ErrNoAuth
		}
		v.tokDigest = sha256.Sum256([]byte(cfg.Token))
		v.hasTok = true
		v.anonymous = false
	case config.AuthNone:
		// Unauthenticated mode.
		if !cfg.AllowUnauthenticated {
			return nil, config.ErrNoAuth
		}
		v.anonymous = true
	default:
		return nil, fmt.Errorf("auth: unknown mode %q", cfg.AuthMode)
	}
	return v, nil
}

// Mode returns the configured auth mode.
func (v *Verifier) Mode() config.AuthMode { return v.mode }

// Required reports whether a credential must be presented.
func (v *Verifier) Required() bool { return v.mode != config.AuthNone }

// Method returns the single method this verifier accepts, or "" when several
// are acceptable (only the case for a token that may be presented as a
// password-style login).
func (v *Verifier) Method() string {
	switch v.mode {
	case config.AuthPassword:
		return MethodPassword
	case config.AuthToken:
		return MethodToken
	}
	return MethodNone
}

// Challenge returns the auth method advertised to the client in the handshake.
func (v *Verifier) Challenge() string { return v.Method() }

// Authenticate validates a credential.
//
// secureTransport must be true when the connection is HTTPS/WSS. When it is
// false and a secret would be transmitted, Authenticate returns ErrInsecure
// rather than leaking the credential onto the wire.
//
// The verifier is stateless across connections: every connection gets exactly
// one attempt (the protocol closes on failure), so there is no global counter
// to exhaust. A per-connection retry limit would live in the session loop,
// not here, otherwise 5 connections would brick the host for everyone.
func (v *Verifier) Authenticate(c Credential, secureTransport bool) error {
	switch v.mode {
	case config.AuthNone:
		return nil

	case config.AuthPassword:
		if !secureTransport {
			return fmt.Errorf("%w: use https:// or wss:// to send a password", ErrInsecure)
		}
		if c.Method != MethodPassword || c.Password == "" {
			return ErrFailed
		}
		sum := sha256.Sum256([]byte(c.Password))
		if subtle.ConstantTimeCompare(sum[:], v.pwDigest[:]) != 1 {
			return ErrFailed
		}
		return nil

	case config.AuthToken:
		if !secureTransport {
			return fmt.Errorf("%w: use https:// or wss:// to send a token", ErrInsecure)
		}
		if c.Method != MethodToken || c.Token == "" {
			return ErrFailed
		}
		sum := sha256.Sum256([]byte(c.Token))
		if subtle.ConstantTimeCompare(sum[:], v.tokDigest[:]) != 1 {
			return ErrFailed
		}
		return nil
	}
	return ErrMethod
}

// String never reveals the configured secret.
func (v *Verifier) String() string {
	return fmt.Sprintf("verifier(mode=%s, secret=%s)", v.mode, Redacted)
}

// Redacted is what replaces every secret in output.
const Redacted = "[redacted]"

// GenerateToken creates a cryptographically strong token suitable for
// `--token`. It is used by `hssh host --generate-token` so operators never
// invent their own credentials.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewTokenVerifier is a convenience for tests and embedders.
func NewTokenVerifier(token string) *Verifier {
	v := &Verifier{mode: config.AuthToken}
	v.tokDigest = sha256.Sum256([]byte(token))
	v.hasTok = true
	return v
}

// SafeMethodName normalises a client-supplied method string.
func SafeMethodName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
