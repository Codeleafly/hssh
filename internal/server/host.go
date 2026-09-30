// Package server implements the HSSH host: it owns the HTTP listener, the
// session manager and the per-connection protocol loop that binds a WebSocket
// to a real PTY.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/httpapi"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/pty"
	"github.com/hssh/hssh/internal/sessions"
	"github.com/hssh/hssh/internal/shell"
	"github.com/hssh/hssh/internal/wsx"
)

// Host is a running HSSH server.
type Host struct {
	cfg      *config.HostConfig
	log      *logging.Logger
	verifier *auth.Verifier
	mgr      *sessions.Manager
	http     *httpapi.Server
	limits   wsx.Limits

	shellSpec shell.Spec
	workDir   string
	// scratchRoot holds per-session working directories when isolation is on.
	scratchRoot string
	scratchMu   sync.Mutex

	// live tracks running sessions so shutdown and resume can find them.
	liveMu sync.Mutex
	live   map[string]*liveSession

	stopOnce sync.Once
	stopped  chan struct{}
	closing  atomic.Bool
}

// Options configures a host.
type Options struct {
	Config   *config.HostConfig
	Log      *logging.Logger
	Verifier *auth.Verifier
	// DisableScratch is used by tests to keep all sessions in one directory.
	DisableScratch bool
}

// New builds a Host. It resolves the shell up front so an unusable
// configuration fails before the port is bound.
func New(o Options) (*Host, error) {
	if o.Config == nil {
		return nil, errors.New("server: config is required")
	}
	if err := o.Config.Validate(); err != nil {
		return nil, err
	}
	if !pty.Supported() {
		return nil, fmt.Errorf("server: no pseudo-terminal support on %s/%s; "+
			"HSSH will not fall back to pipes because a pipe is not a terminal",
			runtime.GOOS, runtime.GOARCH)
	}
	log := o.Log
	if log == nil {
		log = logging.Discard()
	}

	spec, err := shell.Resolve(o.Config.Shell)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	workDir := o.Config.WorkDir
	if workDir == "" {
		workDir = shell.HomeDir()
	}
	if st, err := os.Stat(workDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("server: working directory %q is not usable", workDir)
	}

	verifier := o.Verifier
	if verifier == nil {
		v, err := auth.NewVerifier(o.Config)
		if err != nil {
			return nil, err
		}
		verifier = v
	}

	limits := wsx.DefaultLimits()
	if o.Config.MaxFrameSize >= 1024 {
		limits.MaxFrameBytes = int64(o.Config.MaxFrameSize)
	}
	h := &Host{
		cfg:       o.Config,
		log:       log,
		verifier:  verifier,
		mgr:       sessions.NewManager(o.Config.MaxSessions, o.Config.IdleTimeout),
		limits:    limits,
		shellSpec: spec,
		workDir:   workDir,
		live:      make(map[string]*liveSession),
		stopped:   make(chan struct{}),
	}

	// The session manager's close hook is the single place that guarantees a
	// PTY is released when a session is removed for any reason.
	h.mgr.SetCloseHook(func(s *sessions.Session) {
		h.liveMu.Lock()
		l := h.live[s.ID()]
		delete(h.live, s.ID())
		h.liveMu.Unlock()
		if l != nil {
			// Closing the TerminalSession releases the PTY, hangs up the shell
			// and reaps it. This is the single place that happens.
			// Close the sink first to unblock a wedged writer, then the PTY,
			// then the socket so a blocked readLoop is released.
			if l.sink != nil {
				l.sink.Close()
			}
			l.ts.Close()
			l.mu.Lock()
			c := l.conn
			l.mu.Unlock()
			if c != nil {
				c.Close()
			}
			h.log.Info("session cleaned up", logging.F("session", shortID(s.ID())))
		}
	})

	api, err := httpapi.New(httpapi.Options{
		Config:   o.Config,
		Log:      log,
		Verifier: verifier,
		Limits:   limits,
		Upgrade:  h.upgrade,
		Session:  h.runSession,
	})
	if err != nil {
		return nil, err
	}
	h.http = api
	return h, nil
}

// Shell returns the resolved shell.
func (h *Host) Shell() shell.Spec { return h.shellSpec }

// Sessions exposes the session manager for the `hssh sessions` view.
func (h *Host) Sessions() *sessions.Manager { return h.mgr }

// WorkDir is the default working directory new sessions start in.
func (h *Host) WorkDir() string { return h.workDir }

// BindHost is the address the host was configured to listen on.
func (h *Host) BindHost() string { return h.cfg.Host }

// Start binds the listener and begins serving in the background.
func (h *Host) Start() (string, error) {
	addr, err := h.http.Listen()
	if err != nil {
		return "", err
	}
	go func() {
		if err := h.http.Serve(); err != nil {
			h.log.Error("http server stopped", logging.F("reason", err.Error()))
		}
	}()
	h.startBackgroundWatchers()
	return addr.String(), nil
}

// startBackgroundWatchers runs the idle and slow-client sweeps.
func (h *Host) startBackgroundWatchers() {
	if h.cfg.IdleTimeout > 0 {
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-h.stopped:
					return
				case now := <-t.C:
					for _, id := range h.mgr.Sweep(now) {
						h.log.Info("closing idle session",
							logging.F("session", shortID(id)),
							logging.F("idle_timeout", h.cfg.IdleTimeout.String()),
						)
						h.closeSession(id, "idle timeout")
					}
				}
			}
		}()
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-h.stopped:
				return
			case now := <-t.C:
				ids := h.liveIDs()
				for _, id := range ids {
					if l, ok := h.lookup(id); ok && l.ts.CheckSlowClient(now) {
						h.closeSession(id, "slow client")
					}
				}
			}
		}
	}()
}

// Wait blocks until the host is stopped.
func (h *Host) Wait() { <-h.stopped }

// Shutdown stops the listener, terminates every PTY and waits for the shells
// to be reaped.
func (h *Host) Shutdown(ctx context.Context) error {
	var err error
	h.stopOnce.Do(func() {
		h.closing.Store(true)
		close(h.stopped)
		err = h.http.Shutdown(ctx)

		ids := h.liveIDs()

		for _, id := range ids {
			if l, ok := h.lookup(id); ok {
				h.log.Info("terminating session", logging.F("session", shortID(id)),
					logging.F("reason", "server shutdown"))
				if l.sink != nil {
					l.sink.Close()
				}
				l.ts.Close()
				l.mu.Lock()
				c := l.conn
				l.mu.Unlock()
				if c != nil {
					c.Close()
				}
			}
			// Remove fires the close hook (idempotent with the closes above)
			// so the session table does not leak entries across restarts.
			_, _ = h.mgr.Remove(id)
		}
		h.log.Info("server stopped",
			logging.F("sessions", len(ids)))
	})
	return err
}

// liveIDs snapshots the ids of the live sessions.
func (h *Host) liveIDs() []string {
	h.liveMu.Lock()
	defer h.liveMu.Unlock()
	ids := make([]string, 0, len(h.live))
	for id := range h.live {
		ids = append(ids, id)
	}
	return ids
}

// closeSession removes a session, which triggers the manager's close hook and
// therefore the PTY teardown.
func (h *Host) closeSession(id, reason string) {
	h.log.Info("closing session",
		logging.F("session", shortID(id)),
		logging.F("reason", reason))
	if _, err := h.mgr.Remove(id); err != nil {
		h.log.Debug("close session", logging.F("session", shortID(id)),
			logging.F("reason", err.Error()))
	}
}

// register puts a new session into the live table.
func (h *Host) register(l *liveSession) {
	h.liveMu.Lock()
	h.live[l.sess.ID()] = l
	h.liveMu.Unlock()
}

// lookup returns the live session for an id.
func (h *Host) lookup(id string) (*liveSession, bool) {
	h.liveMu.Lock()
	defer h.liveMu.Unlock()
	l, ok := h.live[id]
	return l, ok
}

// upgrade performs the WebSocket handshake with the configured hardening.
func (h *Host) upgrade(w http.ResponseWriter, r *http.Request) (*wsx.Conn, error) {
	if h.closing.Load() {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return nil, errors.New("server is shutting down")
	}
	if h.cfg.MaxSessions > 0 && h.mgr.Count() >= h.cfg.MaxSessions {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
		return nil, sessions.ErrFull
	}

	up := wsx.Upgrader(h.limits, h.originCheck)
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		// gorilla already wrote the HTTP error response.
		return nil, err
	}
	// Gorilla only offers the subprotocol; it still completes the upgrade
	// when the client offers nothing. Reject that: a plain WebSocket client
	// must not be able to attach to a terminal socket.
	if ws.Subprotocol() != wsx.ProtocolSubprotocol {
		http.Error(w, "unsupported websocket subprotocol", http.StatusBadRequest)
		_ = ws.Close()
		return nil, errors.New("unsupported websocket subprotocol")
	}
	return wsx.NewConn(ws, h.limits), nil
}

// originCheck validates the Host header against the bound address. HSSH v1 is
// CLI only, so a mismatched Host usually means DNS rebinding by a browser.
func (h *Host) originCheck(r *http.Request) bool {
	if !wsx.DefaultOriginCheck(r) {
		h.log.Warn("rejected cross-origin websocket",
			logging.F("origin", r.Header.Get("Origin")),
			logging.F("host", r.Host))
		return false
	}
	return true
}

// sessionDir returns the working directory for a new session. With
// per-session isolation each client gets its own directory under the single
// HSSH home (~/.hssh/sessions/<id>), so `cd` in one session never changes
// another's starting point and nothing is scattered across $HOME or /tmp.
func (h *Host) sessionDir(id string) string {
	if !h.cfg.PerSessionCwd {
		return h.workDir
	}
	h.scratchMu.Lock()
	defer h.scratchMu.Unlock()
	if h.scratchRoot == "" {
		// Single home for all HSSH disk state. HSSH_DIR overrides it in
		// tests. No more /tmp/hssh-sessions-* or <workdir>/.hssh-sessions-*.
		if _, err := config.EnsureHSSHDir(); err != nil {
			h.log.Warn("per-session cwd unavailable",
				logging.F("reason", err.Error()))
			h.cfg.PerSessionCwd = false
			return h.workDir
		}
		h.scratchRoot = config.SessionsRoot()
		h.log.Debug("scratch root", logging.F("path", h.scratchRoot))
	}
	dir := filepath.Join(h.scratchRoot, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		h.log.Warn("per-session cwd failed",
			logging.F("session", shortID(id)),
			logging.F("reason", err.Error()))
		return h.workDir
	}
	return dir
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
