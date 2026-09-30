package server

import (
	"errors"
	"sync"
	"time"

	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/sessions"
	"github.com/hssh/hssh/internal/terminal"
	"github.com/hssh/hssh/internal/wsx"
)

// liveSession is one running terminal session: the PTY, the WebSocket it is
// currently attached to, and the cancellation that tears both down.
//
// It is the unit the resume path operates on: a second client can take over the
// same liveSession, which is how `hssh connect --session=<id>` reattaches
// without starting a second shell.
type liveSession struct {
	sess *sessions.Session
	ts   *terminal.TerminalSession
	sink *wsSink

	mu   sync.Mutex
	conn *wsx.Conn
	// gen is bumped on every attach so a stale goroutine from a previous
	// connection can tell it is no longer the owner and stop.
	gen uint64
}

// attach swaps in a new connection and returns the generation token plus the
// previously attached connection, which the caller must close.
func (l *liveSession) attach(conn *wsx.Conn) (gen uint64, prev *wsx.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gen++
	prev = l.conn
	l.conn = conn
	return l.gen, prev
}

// current reports whether gen is still the owner of this session.
func (l *liveSession) current(gen uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gen == gen
}

// generation returns the current generation token without bumping it.
func (l *liveSession) generation() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gen
}

// send writes a control message on the currently attached connection.
func (l *liveSession) send(msg any) error {
	b, err := protocol.EncodeControl(msg)
	if err != nil {
		return err
	}
	l.mu.Lock()
	c := l.conn
	l.mu.Unlock()
	if c == nil {
		return errClientGone
	}
	return c.WriteText(b)
}

// resumeRequest is the session id the client asked to resume, if any.
// A session id is never a credential on its own.
type resumeRequest struct {
	SessionID string
}

// resumeSession takes over an existing session on a new connection.
//
// Security, in order of importance:
//
//   - The host must have been started with --allow-resume.
//   - The client has already passed the host's normal authentication.
//   - The reconnecting client must come from the same address as the original.
//   - The id must be a well-formed 128-bit hex string.
//
// A session id on its own therefore grants nothing, and a leaked id from a
// different network cannot be used to hijack a shell.
func (h *Host) resumeSession(conn *wsx.Conn, client, sessionID string, log *logging.Logger) error {
	if !h.cfg.AllowResume {
		err := errors.New("this host does not allow resuming sessions")
		_ = h.sendError(conn, protocol.ErrCodeProtocol, err.Error())
		conn.CloseWith(wsxClosePolicyViolation, "resume not allowed")
		return err
	}
	l, ok := h.lookup(sessionID)
	if !ok || l == nil || l.ts.Closed() {
		err := errors.New("no such live session")
		_ = h.sendError(conn, protocol.ErrCodeProtocol, err.Error())
		conn.CloseWith(wsxClosePolicyViolation, "no such session")
		return err
	}
	if l.sess.Snapshot().Client != client {
		log.Warn("resume refused",
			logging.F("session", shortID(sessionID)),
			logging.F("reason", "different client address"))
		err := errors.New("that session belongs to a different client")
		_ = h.sendError(conn, protocol.ErrCodeProtocol, err.Error())
		conn.CloseWith(wsxClosePolicyViolation, "not your session")
		return err
	}

	gen, err := h.attachResume(l, conn, log)
	if err != nil {
		return err
	}

	// The handshake deadline was set for hello/auth only. A resumed session
	// is long-lived, so clear it or every read would time out after 20s.
	_ = conn.ClearReadDeadline()

	// Serve the resumed connection. There is no shell to start and no PTY to
	// create: the existing one keeps running, and the previous WebSocket has
	// already been dropped.
	defer func() {
		if cur, ok := h.lookup(sessionID); ok && cur != nil && cur == l && cur.current(gen) {
			// Only tear down if we are still the owner: a newer client may
			// have taken over while we were closing.
			h.closeSession(sessionID, "resumed session ended")
		}
	}()

	readErr := make(chan error, 1)
	go func() { readErr <- h.readLoop(conn, l.sess, l.ts, log) }()

	// Watch the shell so a resumed client still learns the exit status.
	// TerminalSession.Exit closes after yielding, so mirror pump's pattern.
	shellDone := make(chan struct{})
	exitStatus := make(chan protocol.TerminalExitMsg, 1)
	go func() {
		st, ok := <-l.ts.Exit()
		if ok {
			exitStatus <- protocol.TerminalExitMsg{
				Type:   "exit",
				Code:   st.Code,
				Signal: st.Signal,
			}
		}
		close(shellDone)
	}()

	ticker := time.NewTicker(h.heartbeat())
	defer ticker.Stop()
	for {
		select {
		case err := <-readErr:
			return err
		case st := <-exitStatus:
			log.Info("shell exited",
				logging.F("code", st.Code),
				logging.F("signal", st.Signal))
			_ = h.sendControl(conn, &st)
			conn.CloseWith(wsxCloseNormal, "shell exited")
			<-shellDone
			return nil
		case <-ticker.C:
			if err := conn.WritePing(nil); err != nil {
				return err
			}
			// Same rules as a fresh session: absolute SessionTimeout plus
			// input-idle IdleTimeout. The background sweeper is the backstop,
			// but the connection loop also closes a session that has
			// produced no input for the whole window.
			now := time.Now()
			snap := l.sess.Snapshot()
			if h.cfg.SessionTimeout > 0 && now.Sub(snap.Created) > h.cfg.SessionTimeout {
				log.Info("closing resumed session: session timeout", logging.F("timeout", h.cfg.SessionTimeout.String()))
				_ = h.sendControl(conn, &protocol.DisconnectMsg{
					Type: "disconnect", Reason: "session timeout", Forced: true,
				})
				conn.CloseWith(wsxClosePolicyViolation, "session timeout")
				return nil
			}
			if h.cfg.IdleTimeout > 0 &&
				now.Sub(snap.LastSeen) > h.cfg.IdleTimeout {
				log.Info("closing idle resumed session", logging.F("timeout", h.cfg.IdleTimeout.String()))
				_ = h.sendControl(conn, &protocol.DisconnectMsg{
					Type: "disconnect", Reason: "idle timeout", Forced: true,
				})
				conn.CloseWith(wsxClosePolicyViolation, "idle timeout")
				return nil
			}
		}
	}
}

func (h *Host) heartbeat() time.Duration {
	if h.cfg.Heartbeat > 0 {
		return h.cfg.Heartbeat
	}
	return 30 * time.Second
}

// idleTimeout returns the input-idle timeout. SessionTimeout is absolute and
// is checked separately against Created.
func (h *Host) idleTimeout() time.Duration {
	return h.cfg.IdleTimeout
}

// attachResume rebinds an existing session to a fresh connection.
func (h *Host) attachResume(l *liveSession, conn *wsx.Conn, log *logging.Logger) (uint64, error) {
	gen, prev := l.attach(conn)
	if prev != nil {
		// The old peer is going away; drop it without a close handshake so the
		// new connection is not delayed.
		prev.Close()
	}
	l.sink = newWSSink(conn, h.limits.MaxFrameBytes)
	l.ts.SetSink(l.sink)

	info := l.sess.Snapshot()
	if err := l.send(&protocol.SessionInfoMsg{
		Type:     "session_info",
		Session:  l.sess.ID(),
		Shell:    l.ts.ShellLabel(),
		Cwd:      info.Cwd,
		Cols:     info.Cols,
		Rows:     info.Rows,
		Client:   info.Client,
		Started:  info.Created,
		LastSeen: time.Now(),
		PID:      l.ts.Pid(),
	}); err != nil {
		return gen, err
	}
	log.Info("session resumed",
		logging.F("session", shortID(l.sess.ID())),
		logging.F("shell", l.ts.ShellLabel()),
	)
	return gen, nil
}
