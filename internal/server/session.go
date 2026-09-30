package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/sessions"
	"github.com/hssh/hssh/internal/shell"
	"github.com/hssh/hssh/internal/terminal"
	"github.com/hssh/hssh/internal/wsx"
)

// handshakeTimeout bounds the hello/auth/terminal_start exchange so a client
// cannot hold a session slot open by connecting and saying nothing.
const handshakeTimeout = 20 * time.Second

// errClientGone signals a clean client disconnect.
var errClientGone = errors.New("client disconnected")

// errInvalidSessionID is returned when --session=<id> is not 32 lowercase hex.
var errInvalidSessionID = errors.New("invalid session id: must be 32 lowercase hex characters")

// runSession owns one WebSocket from upgrade to close. Everything about the
// session happens here: version negotiation, authentication, PTY allocation,
// the input pump, the heartbeat, and guaranteed cleanup.
func (h *Host) runSession(conn *wsx.Conn, r *http.Request) error {
	remote := remoteAddr(r)
	log := h.log.With(logging.F("client", remote))

	// The socket is the only channel for the handshake, so give it a deadline
	// and then clear it once the session is live.
	conn.SetReadLimit(h.limits.MaxFrameBytes)
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	// ---- Step 1: protocol negotiation ------------------------------------
	if _, err := h.exchangeHello(conn, log); err != nil {
		return err
	}

	// ---- Step 2: authentication negotiation ------------------------------
	secure := conn.IsTLS()
	resume, err := h.exchangeAuth(conn, log, secure)
	if err != nil {
		if errors.Is(err, errInvalidSessionID) {
			_ = h.sendError(conn, protocol.ErrCodeProtocol, err.Error())
			conn.CloseWith(wsxClosePolicyViolation, "invalid session id")
			return err
		}
		_ = h.sendError(conn, protocol.ErrCodeAuth, err.Error())
		conn.CloseWith(wsxClosePolicyViolation, "authentication failed")
		return err
	}
	log.Info("authenticated",
		logging.F("method", h.verifier.Challenge()),
		logging.F("transport", transportName(secure)))

	// ---- Step 2b: resume an existing session, if asked --------------------
	//
	// A session id is never a credential. Resuming requires the same client
	// address, and the client has already passed the host's authentication.
	if resume != nil && resume.SessionID != "" {
		return h.resumeSession(conn, remote, resume.SessionID, log)
	}

	// ---- Step 3: allocate a session and a PTY ----------------------------
	// NOTE: the handshake deadline stays armed through terminal_start so an
	// authenticated client cannot hold a session-table slot open by staying
	// silent. It is cleared only after readTerminalStart succeeds.
	sess, err := h.mgr.Create(sessions.Options{
		Client: remote,
		Cols:   80,
		Rows:   24,
		Auth:   h.verifier.Challenge(),
	})
	if err != nil {
		if errors.Is(err, sessions.ErrFull) {
			_ = h.sendError(conn, protocol.ErrCodeSessionLimit,
				"the host is already running the maximum number of sessions")
			conn.CloseWith(wsxCloseTryAgainLater, "session limit reached")
			return err
		}
		return err
	}
	slog := log.With(logging.F("session", shortID(sess.ID())))
	slog.Info("client connected")

	// From here on every exit path removes the session, unless another
	// connection has taken it over via resume (gen bump). Only the current
	// owner may remove, otherwise a resume would be killed by the previous
	// connection's teardown racing it (PID 0 / new shell bug).
	var l *liveSession
	var myGen uint64
	defer func() {
		if l != nil {
			if cur, ok := h.lookup(sess.ID()); ok && cur == l && cur.current(myGen) {
				if _, rmErr := h.mgr.Remove(sess.ID()); rmErr != nil {
					slog.Debug("session remove", logging.F("reason", rmErr.Error()))
				}
				slog.Info("client disconnected")
			} else {
				slog.Debug("previous connection ended after resume, leaving session live")
			}
			return
		}
		// No live session yet (handshake / terminal_start failed): nothing
		// could have resumed it, so remove unconditionally.
		if _, rmErr := h.mgr.Remove(sess.ID()); rmErr != nil {
			slog.Debug("session remove", logging.F("reason", rmErr.Error()))
		}
		slog.Info("client disconnected")
	}()

	// ---- Step 4: terminal start, or a session-table query ----------------
	start, err := h.readTerminalStart(conn, sess, slog)
	if err != nil {
		return err
	}
	_ = conn.ClearReadDeadline()

	sink := newWSSink(conn, h.limits.MaxFrameBytes)
	ts, err := h.startPTY(sess, start, sink, slog)
	if err != nil {
		_ = h.sendError(conn, errorCodeFor(err), err.Error())
		conn.CloseWith(wsxCloseInternalErr, "could not start a terminal")
		return err
	}
	l = &liveSession{sess: sess, ts: ts, sink: sink, conn: conn}
	h.register(l)
	myGen = l.generation()

	if err := h.sendControl(conn, &protocol.SessionInfoMsg{
		Type:     "session_info",
		Session:  sess.ID(),
		Shell:    ts.ShellLabel(),
		Cwd:      sess.Snapshot().Cwd,
		Cols:     start.Cols,
		Rows:     start.Rows,
		Client:   remote,
		Started:  sess.Snapshot().Created,
		LastSeen: time.Now(),
		PID:      ts.Pid(),
	}); err != nil {
		return err
	}

	// ---- Step 5: run the session ----------------------------------------
	return h.pump(conn, sess, ts, slog)
}

// exchangeHello reads the client's hello and validates the protocol version.
func (h *Host) exchangeHello(conn *wsx.Conn, log *logging.Logger) (*protocol.HelloMsg, error) {
	frame, err := h.readFrame(conn)
	if err != nil {
		return nil, err
	}
	if frame.Op != protocol.MessageHello {
		_ = h.sendError(conn, protocol.ErrCodeProtocol,
			"expected a hello message first")
		conn.CloseWith(wsxClosePolicyViolation, "handshake failed")
		return nil, fmt.Errorf("%w: got %s", protocol.ErrBadJSON, frame.Op)
	}
	var hello protocol.HelloMsg
	if err := protocol.DecodeControl(frame, &hello); err != nil {
		_ = h.sendError(conn, protocol.ErrCodeProtocol, "malformed hello message")
		return nil, err
	}
	// Forward compatibility: HSSH/1 clients are accepted. A client that speaks
	// a version this host does not implement is rejected cleanly rather than
	// mis-parsed.
	if hello.Protocol != "" && !strings.HasPrefix(hello.Protocol, "HSSH/1") {
		_ = h.sendError(conn, protocol.ErrCodeProtocol, fmt.Sprintf(
			"this host speaks %s; client offered %s", protocol.Version, hello.Protocol))
		conn.CloseWith(wsxClosePolicyViolation, "unsupported protocol version")
		return nil, fmt.Errorf("protocol: unsupported version %q (host speaks %s)",
			hello.Protocol, protocol.Version)
	}
	log.Debug("handshake",
		logging.F("protocol", hello.Protocol),
		logging.F("client_version", hello.Version),
		logging.F("client_os", hello.OS),
	)
	return &hello, nil
}

// exchangeAuth performs the credential exchange and returns the session id the
// client asked to resume, if any.
func (h *Host) exchangeAuth(conn *wsx.Conn, log *logging.Logger, secure bool) (*resumeRequest, error) {
	// Tell the client which method to use before it sends anything.
	if err := h.sendControl(conn, &protocol.AuthResultMsg{
		Type:     "auth_result",
		OK:       false,
		Error:    "authentication required: " + h.verifier.Challenge(),
		Protocol: protocol.Version,
	}); err != nil {
		return nil, err
	}

	frame, err := h.readFrame(conn)
	if err != nil {
		return nil, err
	}
	if frame.Op != protocol.MessageAuth {
		_ = h.sendError(conn, protocol.ErrCodeProtocol, "expected an auth message")
		return nil, fmt.Errorf("%w: got %s", protocol.ErrBadJSON, frame.Op)
	}
	var msg protocol.AuthMsg
	if err := protocol.DecodeControl(frame, &msg); err != nil {
		return nil, err
	}

	cred := auth.Credential{
		Method:   auth.SafeMethodName(msg.Method),
		Password: msg.Password,
		Token:    msg.Token,
	}
	if err := h.verifier.Authenticate(cred, secure); err != nil {
		// The message is generic on purpose: a client must not be able to tell
		// "wrong password" from "wrong username" from "unknown method".
		log.Warn("authentication failed", logging.F("method", cred.Method))
		return nil, auth.ErrFailed
	}

	// Drop the credential as soon as it is no longer needed.
	msg.Password, msg.Token = "", ""

	if err := h.sendControl(conn, &protocol.AuthResultMsg{
		Type:     "auth_result",
		OK:       true,
		Protocol: protocol.Version,
	}); err != nil {
		return nil, err
	}
	// Only a 128-bit id of the right shape is even considered for a resume.
	// A non-empty but malformed id is a client bug: fail fast with a friendly
	// error instead of silently starting a new shell and leaving the client
	// waiting for terminal_start (which caused a 15s i/o timeout).
	if id := msg.Resume; id != "" {
		if !validSessionID(id) {
			return nil, fmt.Errorf("%w: %q", errInvalidSessionID, id)
		}
		return &resumeRequest{SessionID: id}, nil
	}
	return nil, nil
}

// validSessionID rejects anything that is not exactly 32 lowercase hex
// characters, so a hostile client cannot turn this field into a lookup oracle.
func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// readTerminalStart reads and validates the terminal_start request.
//
// A client that only wants to inspect the host (the `hssh sessions` command)
// sends sessions_request instead. That is answered and the connection is then
// closed, so an introspection client never allocates a PTY.
func (h *Host) readTerminalStart(conn *wsx.Conn, sess *sessions.Session, log *logging.Logger) (*protocol.TerminalStartMsg, error) {
	frame, err := h.readFrame(conn)
	if err != nil {
		return nil, err
	}
	if frame.Op == protocol.MessageSessionsRequest {
		if err := h.sendControl(conn, h.sessionListMsg(sess.ID())); err != nil {
			return nil, err
		}
		conn.CloseWith(wsxCloseNormal, "session table delivered")
		return nil, errClientGone
	}
	if frame.Op != protocol.MessageTerminalStart {
		_ = h.sendError(conn, protocol.ErrCodeProtocol, "expected a terminal_start message")
		return nil, fmt.Errorf("%w: got %s", protocol.ErrBadJSON, frame.Op)
	}
	var msg protocol.TerminalStartMsg
	if err := protocol.DecodeControl(frame, &msg); err != nil {
		return nil, err
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		msg.Cols, msg.Rows = 80, 24
	}
	if msg.Cols > 1000 {
		msg.Cols = 1000
	}
	if msg.Rows > 1000 {
		msg.Rows = 1000
	}
	return &msg, nil
}

// startPTY allocates the PTY and launches the real shell.
func (h *Host) startPTY(sess *sessions.Session, start *protocol.TerminalStartMsg, sink terminal.OutputSink, log *logging.Logger) (*terminal.TerminalSession, error) {
	dir, err := h.resolveCwd(sess.ID(), start.Cwd)
	if err != nil {
		return nil, err
	}

	term := start.Term
	if term == "" {
		term = "xterm-256color"
	}
	// TERM values come from a client, so keep them to a sane, printable shape
	// instead of forwarding arbitrary bytes into the child environment.
	if !validTerm(term) {
		term = "xterm-256color"
	}

	// Per-session shell history under the single HSSH home so concurrent
	// shells never share/truncate ~/.bash_history. Best effort: if the home
	// cannot be created, fall back to the default shell history.
	histFile := ""
	if _, err := config.EnsureHSSHDir(); err == nil {
		histFile = config.HistoryFile(sess.ID())
		if f, ferr := os.OpenFile(histFile, os.O_CREATE|os.O_APPEND, 0o600); ferr == nil {
			_ = f.Close()
		} else {
			histFile = ""
		}
	}
	envExtra := map[string]string{
		"TERM": term,
		// PWD must describe the child's real directory. DefaultEnv passes the
		// server process's own PWD through, which is stale whenever the
		// session starts anywhere else (home default, --workdir, --cwd,
		// per-session scratch). Extras win the merge, so this corrects it.
		"PWD":          dir,
		"HSSH_SESSION": sess.ID(),
		"HSSH_CLIENT":  clientDesc(start.ColorScheme),
	}
	if histFile != "" {
		envExtra["HISTFILE"] = histFile
	}

	ts, err := terminal.NewSession(sess.ID(), terminal.StartOptions{
		Shell:    h.shellSpec,
		Env:      shell.DefaultEnv(nil),
		EnvExtra: envExtra,
		Dir:      dir,
		Cols:     start.Cols,
		Rows:     start.Rows,
		Sink:     sink,
		Log:      log,
		// Live cwd tracking: the shell reports directory changes with
		// OSC 7 (VS Code-style shell integration); the session record
		// follows, which is what `hssh sessions` displays.
		OnCwd: func(d string) { sess.SetCwd(d) },
		Pump: terminal.PumpConfig{
			MaxQueuedBytes:    h.cfg.OutputBuffer,
			SlowClientTimeout: 30 * time.Second,
		},
	})
	if err != nil {
		return nil, err
	}
	sess.SetShell(ts.ShellLabel(), ts.Pid())
	sess.SetSize(start.Cols, start.Rows)
	sess.SetCwd(dir)
	sess.SetState(sessions.StateRunning)
	return ts, nil
}

// maxCwdLen caps a client-supplied working directory. The control frame is
// already limited to 1 MiB, but a path longer than this is never legitimate.
const maxCwdLen = 4096

// resolveCwd decides the directory a new shell starts in.
//
//   - Empty: the host default (per-session scratch dir when isolation is on,
//     otherwise --workdir, else home).
//   - Non-empty: a path on the SERVER. Relative paths resolve against the
//     host working directory, never against the server process's own CWD,
//     so the result is predictable no matter where the host was launched.
//
// Anything unusable is a hard error, not a silent fallback: a typo in
// --cwd must fail loudly rather than drop the user in an unexpected
// directory.
func (h *Host) resolveCwd(sessID, cwd string) (string, error) {
	if cwd == "" {
		return h.sessionDir(sessID), nil
	}
	if len(cwd) > maxCwdLen {
		return "", fmt.Errorf("working directory is too long (%d bytes, max %d)", len(cwd), maxCwdLen)
	}
	if h.cfg.PerSessionCwd {
		return "", errors.New("this host isolates every session in a private directory, so --cwd is not honoured")
	}
	path := cwd
	if !filepath.IsAbs(path) {
		path = filepath.Join(h.workDir, path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("working directory %q is not usable: %v", cwd, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("working directory %q is not a directory", cwd)
	}
	return path, nil
}

// pump runs the live session: input from the client, control messages, and the
// shell's exit, until either side ends.
func (h *Host) pump(conn *wsx.Conn, sess *sessions.Session, ts *terminal.TerminalSession, log *logging.Logger) error {
	// Tell the reader when the pump ends so a blocked Read is released by
	// closing the connection.
	readErr := make(chan error, 1)
	go func() { readErr <- h.readLoop(conn, sess, ts, log) }()

	hb := h.cfg.Heartbeat
	if hb <= 0 {
		hb = 30 * time.Second
	}
	ticker := time.NewTicker(hb)
	defer ticker.Stop()

	// Watch the shell so we report its exit and clean up promptly.
	shellDone := make(chan struct{})
	var exitStatus = make(chan protocol.TerminalExitMsg, 1)
	go func() {
		st, ok := <-ts.Exit()
		if ok {
			exitStatus <- protocol.TerminalExitMsg{
				Type:   "exit",
				Code:   st.Code,
				Signal: st.Signal,
			}
		}
		close(shellDone)
	}()

	snap := sess.Snapshot()
	created := snap.Created

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
			// Protocol-level ping: cheap, and it keeps NAT/proxies from
			// dropping an idle terminal.
			if err := conn.WritePing(nil); err != nil {
				return fmt.Errorf("heartbeat write failed: %w", err)
			}
			now := time.Now()
			snap := sess.Snapshot()
			// Absolute lifetime: SessionTimeout counts from creation,
			// independent of activity.
			if h.cfg.SessionTimeout > 0 && now.Sub(created) > h.cfg.SessionTimeout {
				log.Info("closing session: session timeout", logging.F("timeout", h.cfg.SessionTimeout.String()))
				_ = h.sendControl(conn, &protocol.DisconnectMsg{
					Type: "disconnect", Reason: "session timeout", Forced: true,
				})
				conn.CloseWith(wsxClosePolicyViolation, "session timeout")
				return nil
			}
			// Idle timeout: no input/control frames for the whole window.
			// sess.LastSeen is touched by readLoop on every input/control
			// frame, so this tracks input activity. The background sweeper
			// is the backstop for wedged readers.
			if h.cfg.IdleTimeout > 0 && now.Sub(snap.LastSeen) > h.cfg.IdleTimeout {
				log.Info("closing idle session", logging.F("timeout", h.cfg.IdleTimeout.String()))
				_ = h.sendControl(conn, &protocol.DisconnectMsg{
					Type: "disconnect", Reason: "idle timeout", Forced: true,
				})
				conn.CloseWith(wsxClosePolicyViolation, "idle timeout")
				return nil
			}
		}
	}
}

// readLoop consumes client frames until the socket dies.
func (h *Host) readLoop(conn *wsx.Conn, sess *sessions.Session, ts *terminal.TerminalSession, log *logging.Logger) error {
	for {
		raw, binary, err := conn.ReadMessage()
		if err != nil {
			return wsx.NormaliseClose(err)
		}
		frame, err := protocol.Decode(raw)
		if err != nil {
			log.Warn("dropping malformed frame", logging.F("reason", err.Error()))
			continue
		}

		if binary || frame.Op.IsPayload() {
			if frame.Op == protocol.PayloadInput {
				sess.Touch()
				n, werr := ts.WriteInput(frame.Data)
				sess.AddBytes(int64(n), 0)
				if werr != nil {
					return werr
				}
			}
			continue
		}

		sess.Touch()
		switch frame.Op {
		case protocol.PayloadOutput:
			// A client must never be able to inject server->client output.
			log.Warn("ignoring output frame from client")

		case protocol.MessageTerminalInput:
			// An alternative input channel: the same opaque bytes, carried on a
			// binary frame so no encoding is added to the keystroke path.
			if len(frame.Data) > 0 {
				n, werr := ts.WriteInput(frame.Data)
				sess.AddBytes(int64(n), 0)
				if werr != nil {
					return werr
				}
			}

		case protocol.MessageTerminalResize:
			var msg protocol.TerminalResizeMsg
			if err := protocol.DecodeControl(frame, &msg); err != nil {
				continue
			}
			if err := ts.Resize(msg.Cols, msg.Rows); err != nil {
				log.Warn("resize failed", logging.F("reason", err.Error()))
				_ = h.sendError(conn, protocol.ErrCodeResize,
					"could not resize the terminal: "+err.Error())
				continue
			}
			sess.SetSize(msg.Cols, msg.Rows)
			log.Debug("terminal resized",
				logging.F("size", fmt.Sprintf("%dx%d", msg.Cols, msg.Rows)))

		case protocol.MessageTerminalSignal:
			var msg protocol.TerminalSignalMsg
			if err := protocol.DecodeControl(frame, &msg); err != nil {
				continue
			}
			if err := ts.Signal(msg.Name); err != nil {
				log.Warn("signal failed",
					logging.F("signal", msg.Name),
					logging.F("reason", err.Error()))
			}

		case protocol.MessagePing:
			var msg protocol.PingMsg
			_ = protocol.DecodeControl(frame, &msg)
			_ = h.sendControl(conn, &protocol.PongMsg{Type: "pong", Seq: msg.Seq, TS: nowMillis()})

		case protocol.MessagePong:
			// nothing to do; the pong handler already refreshed activity

		case protocol.MessageDisconnect:
			log.Info("client requested disconnect")
			return errClientGone

		case protocol.MessageSessionsRequest:
			// `hssh sessions`. Only metadata is returned: ids, clients, sizes
			// and lifetimes. No terminal content and no credentials ever leave
			// the host through this path.
			if err := h.sendControl(conn, h.sessionListMsg(sess.ID())); err != nil {
				return err
			}

		case protocol.MessageError:
			log.Warn("client reported an error")

		default:
			log.Warn("unexpected message", logging.F("type", frame.Op.String()))
		}
	}
}

// readFrame reads a single frame, used during the handshake.
func (h *Host) readFrame(conn *wsx.Conn) (protocol.Frame, error) {
	raw, _, err := conn.ReadMessage()
	if err != nil {
		return protocol.Frame{}, wsx.NormaliseClose(err)
	}
	if len(raw) > protocol.MaxControlFrame {
		return protocol.Frame{}, protocol.ErrFrameTooBig
	}
	frame, err := protocol.Decode(raw)
	if err != nil {
		return protocol.Frame{}, err
	}
	if frame.Op.IsPayload() {
		return protocol.Frame{}, fmt.Errorf("expected a control message, got %s", frame.Op)
	}
	return frame, nil
}

// sessionListMsg renders the host's live session table for a connected client.
// selfID, when non-empty, is the requesting session and is flagged rather than
// hidden, so the table shows the same rows for everyone.
func (h *Host) sessionListMsg(selfID string) *protocol.SessionsListMsg {
	infos := h.mgr.List()
	out := &protocol.SessionsListMsg{
		Type:     "sessions_list",
		Sessions: make([]protocol.SessionEntry, 0, len(infos)),
		Max:      h.cfg.MaxSessions,
	}
	for _, i := range infos {
		out.Sessions = append(out.Sessions, protocol.SessionEntry{
			Self:     i.ID == selfID,
			ID:       i.ID,
			Client:   i.Client,
			Shell:    i.Shell,
			Cwd:      i.Cwd,
			Cols:     i.Cols,
			Rows:     i.Rows,
			Auth:     i.Auth,
			State:    string(i.State),
			Created:  i.Created,
			LastSeen: i.LastSeen,
			PID:      i.PID,
			BytesIn:  i.BytesIn,
			BytesOut: i.BytesOut,
		})
	}
	return out
}

func (h *Host) sendControl(conn *wsx.Conn, msg any) error {
	b, err := protocol.EncodeControl(msg)
	if err != nil {
		return err
	}
	return conn.WriteText(b)
}

func (h *Host) sendError(conn *wsx.Conn, code, msg string) error {
	return h.sendControl(conn, protocol.NewError(code, msg))
}

func errorCodeFor(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "PTY"), strings.Contains(msg, "pseudo-terminal"):
		return protocol.ErrCodePTY
	case strings.Contains(msg, "shell"):
		return protocol.ErrCodeShell
	default:
		return protocol.ErrCodeInternal
	}
}

// validTerm keeps client-supplied TERM values to a conservative shape.
func validTerm(t string) bool {
	if len(t) == 0 || len(t) > 64 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func clientDesc(scheme string) string {
	if scheme == "" {
		return "unknown"
	}
	return scheme
}

func transportName(secure bool) string {
	if secure {
		return "tls"
	}
	return "plaintext"
}

func remoteAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	// Fallback for non host:port forms (unix sockets, tests).
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// WebSocket close codes used by HSSH. 1008 (policy violation) and 1013 (try
// again later) are from the IANA registry and are the right signals here.
const (
	wsxCloseNormal          = 1000
	wsxClosePolicyViolation = 1008
	wsxCloseInternalErr     = 1011
	wsxCloseTryAgainLater   = 1013
)
