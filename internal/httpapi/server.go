// Package httpapi implements the HSSH HTTP/HTTPS surface: discovery, health,
// and the WebSocket upgrade endpoint.
//
// The terminal itself never travels over HTTP. HTTP is used once, for the
// handshake, and then the connection is upgraded to a WebSocket that stays open
// for the whole session.
package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/wsx"
)

// Server is the HTTP/HTTPS front end.
type Server struct {
	cfg      *config.HostConfig
	log      *logging.Logger
	verifier *auth.Verifier
	upgrader *websocketUpgrader

	mux      *http.ServeMux
	httpSrv  *http.Server
	listener net.Listener

	// upgraderFn and sessionFn are injected by the server package so the HTTP
	// layer does not have to import the session machinery (and vice versa).
	upgraderFn func(http.ResponseWriter, *http.Request) (*wsx.Conn, error)
	sessionFn  func(conn *wsx.Conn, r *http.Request) error

	connCounter atomic.Uint64
	started     time.Time
	shutdown    atomic.Bool
}

// Options wires the HTTP server to the rest of the host.
type Options struct {
	Config   *config.HostConfig
	Log      *logging.Logger
	Verifier *auth.Verifier
	Limits   wsx.Limits
	// Upgrade and Session are supplied by the server package.
	Upgrade func(http.ResponseWriter, *http.Request) (*wsx.Conn, error)
	Session func(conn *wsx.Conn, r *http.Request) error
}

// New builds the HTTP layer.
func New(o Options) (*Server, error) {
	if o.Config == nil {
		return nil, errors.New("httpapi: config is required")
	}
	if o.Upgrade == nil {
		return nil, errors.New("httpapi: upgrade handler is required")
	}
	if o.Session == nil {
		return nil, errors.New("httpapi: session handler is required")
	}
	log := o.Log
	if log == nil {
		log = logging.Discard()
	}

	s := &Server{
		cfg:        o.Config,
		log:        log,
		verifier:   o.Verifier,
		upgraderFn: o.Upgrade,
		sessionFn:  o.Session,
		mux:        http.NewServeMux(),
		started:    time.Now(),
	}
	s.upgrader = &websocketUpgrader{limits: o.Limits}

	s.routes()

	s.httpSrv = &http.Server{
		Handler:           s.withSecurityHeaders(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: an upgraded WebSocket is long-lived by design and
		// would otherwise be killed mid-session.
		MaxHeaderBytes: 1 << 16,
		ErrorLog:       nil,
	}
	return s, nil
}

// Listen binds the address. TLS is configured when a cert and key are present.
func (s *Server) Listen() (net.Addr, error) {
	ln, err := net.Listen("tcp", s.cfg.Addr())
	if err != nil {
		return nil, err
	}
	if s.cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("httpapi: loading TLS key pair: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	s.listener = ln
	return ln.Addr(), nil
}

// Serve runs the accept loop until Shutdown is called.
func (s *Server) Serve() error {
	if s.listener == nil {
		if _, err := s.Listen(); err != nil {
			return err
		}
	}
	s.log.Info("http listening",
		logging.F("address", s.listener.Addr().String()),
		logging.F("tls", s.cfg.TLSEnabled()),
	)
	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdown.Store(true)
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) routes() {
	s.mux.HandleFunc(wsx.HealthEndpoint, s.handleHealth)
	s.mux.HandleFunc(wsx.WellKnownEndpoint, s.handleConnect)
	s.mux.HandleFunc("/version", s.handleHealth)
	s.mux.HandleFunc("/", s.handleRoot)
}

// HealthResponse is the JSON body of GET /health. The shape is part of the
// public contract: clients use it for discovery.
type HealthResponse struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Protocol  string   `json:"protocol"`
	WebSocket bool     `json:"websocket"`
	TLS       bool     `json:"tls"`
	Auth      string   `json:"auth"`
	Uptime    float64  `json:"uptime_seconds"`
	Endpoints []string `json:"endpoints"`
}

// handleHealth serves discovery and liveness.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	resp := HealthResponse{
		Name:      protocol.Name,
		Version:   protocol.VersionString,
		Protocol:  protocol.Version,
		WebSocket: true,
		TLS:       r.TLS != nil,
		Auth:      string(s.cfg.AuthMode),
		Uptime:    time.Since(s.started).Seconds(),
		Endpoints: []string{wsx.HealthEndpoint, wsx.WellKnownEndpoint},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRoot is a friendly index so a human who types the URL sees something
// useful. It never lists sessions.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":      protocol.Name,
		"version":   protocol.VersionString,
		"protocol":  protocol.Version,
		"endpoints": []string{wsx.HealthEndpoint, wsx.WellKnownEndpoint},
		"websocket": wsx.ProtocolSubprotocol,
		"usage":     "hssh connect=" + schemeOf(r) + "://" + r.Host,
	})
}

// handleConnect performs the WebSocket upgrade. The terminal session itself is
// negotiated over the socket; this endpoint's whole job is to say yes or no.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	// Reject obvious scanner traffic before spending any resources.
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "expected a WebSocket upgrade",
		})
		return
	}

	conn, err := s.upgraderFn(w, r)
	if err != nil {
		// Upgrade already wrote an HTTP error response.
		s.log.Warn("websocket upgrade rejected",
			logging.F("remote", clientIP(r)),
			logging.F("reason", err.Error()),
		)
		return
	}
	// The session loop takes ownership of the connection from here.
	s.connCounter.Add(1)
	go s.serveConn(conn, r)
}

// serveConn runs one client session to completion. It lives here so the HTTP
// package owns the connection lifetime end to end and there is no path where a
// socket is left dangling.
func (s *Server) serveConn(conn *wsx.Conn, r *http.Request) {
	defer conn.Close()
	if err := s.sessionFn(conn, r); err != nil {
		s.log.Debug("session ended",
			logging.F("remote", clientIP(r)),
			logging.F("reason", err.Error()),
		)
	}
}

// websocketUpgrader holds the shared limits for the upgrade path.
type websocketUpgrader struct {
	limits wsx.Limits
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// HSSH v1 is CLI-to-CLI. Advertising nothing indexable keeps the host
		// from being usefully probed by a browser.
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// No CORS headers: a browser must not be able to open a session here.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = jsonEncode(w, v)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"error": "method not allowed",
	})
}

func clientIP(r *http.Request) string {
	// Trust X-Forwarded-For only when the operator put a proxy in front; HSSH
	// does not use the header for authentication, only for display.
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// NormalizeAddr turns "host:port" into something net.Dial can use, adding the
// default HTTP port when it is missing.
func NormalizeAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	} else if strings.Contains(err.Error(), "missing port in address") {
		return net.JoinHostPort(addr, "80")
	}
	return addr
}

// ParsePort extracts a numeric port from a "host:port" string.
func ParsePort(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}
