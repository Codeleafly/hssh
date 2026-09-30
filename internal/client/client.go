// Package client implements the HSSH CLI client: handshake, authentication,
// raw-mode keyboard capture, and pass-through rendering of the remote PTY's
// bytes to the local terminal.
//
// The client never emulates a terminal. It puts the local tty into raw mode so
// every keystroke reaches the server, and writes the server's bytes straight to
// stdout. Colour, cursor movement, the alternate screen buffer and UTF-8 all
// work because the real terminal does the rendering, exactly as with ssh.
package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/terminal"
	"github.com/hssh/hssh/internal/wsx"
)

// Errors surfaced to the CLI.
var (
	ErrNotConnected = errors.New("not connected")
	ErrProtocol     = errors.New("the server speaks a different HSSH protocol version")
	ErrAuthFailed   = errors.New("authentication failed")
	ErrInsecureAuth = errors.New("refusing to send a password over an unencrypted connection")
	ErrTerminal     = errors.New("the local terminal could not be configured")
)

// ConnectError carries a human-readable diagnosis of a failed connection.
type ConnectError struct {
	Target  string
	Reason  string
	Hint    string
	Wrapped error
}

func (e *ConnectError) Error() string {
	var b strings.Builder
	b.WriteString("cannot connect to the HSSH host\n\n")
	fmt.Fprintf(&b, "  Target:  %s\n", e.Target)
	if e.Reason != "" {
		fmt.Fprintf(&b, "  Reason:  %s\n", e.Reason)
	}
	if e.Hint != "" {
		fmt.Fprintf(&b, "\n%s\n", e.Hint)
	}
	return b.String()
}

func (e *ConnectError) Unwrap() error { return e.Wrapped }

// Client is a connected HSSH session.
type Client struct {
	cfg    *config.ClientConfig
	log    *logging.Logger
	conn   *wsx.Conn
	out    io.Writer
	in     *os.File
	term   *terminal.State
	parser *terminal.EscapeParser

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup

	// remoteExit is the shell's exit status once the session ends.
	remoteExit chan protocol.TerminalExitMsg

	// gotInfo is set once session_info arrives. earlyErr keeps the first
	// server error, so a session rejected before it started (bad --cwd,
	// failed PTY) exits non-zero instead of a misleading "Disconnected".
	gotInfo  bool
	earlyErr string

	// Detected holds info about the host from GET /health.
	Detected *HostInfo
}

// HostInfo is the discovery document from GET /health.
type HostInfo struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Protocol  string   `json:"protocol"`
	WebSocket bool     `json:"websocket"`
	TLS       bool     `json:"tls"`
	Auth      string   `json:"auth"`
	Uptime    float64  `json:"uptime_seconds"`
	Endpoints []string `json:"endpoints"`
}

// Options configure a client.
type Options struct {
	Config *config.ClientConfig
	Log    *logging.Logger
	// Out defaults to os.Stdout; In defaults to os.Stdin. Tests override both.
	Out io.Writer
	In  *os.File
	// Prompt receives the connection banner before raw mode is entered.
	Prompt io.Writer
}

// New builds a client from validated options.
func New(o Options) (*Client, error) {
	if o.Config == nil {
		return nil, errors.New("client: config is required")
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.In == nil {
		o.In = os.Stdin
	}
	log := o.Log
	if log == nil {
		log = logging.Discard()
	}
	var keys [][]byte
	if len(o.Config.Disconnect) == 0 {
		keys = terminal.DefaultDisconnectKeys
	} else {
		keys = make([][]byte, 0, len(o.Config.Disconnect))
		for _, k := range o.Config.Disconnect {
			keys = append(keys, []byte(k))
		}
	}
	return &Client{
		cfg:        o.Config,
		log:        log,
		out:        o.Out,
		in:         o.In,
		parser:     terminal.NewEscapeParser(keys...),
		closed:     make(chan struct{}),
		remoteExit: make(chan protocol.TerminalExitMsg, 1),
	}, nil
}

// Connect performs discovery, the WebSocket handshake and authentication.
//
// The HTTP request is a real request against the /health endpoint, which is how
// the client learns the host's protocol version and auth method before
// committing to a socket.
func (c *Client) Connect() error {
	target := c.cfg.URL

	// ---- Discovery -------------------------------------------------------
	info, err := c.discover(target)
	if err != nil {
		return err
	}
	c.Detected = info

	if info.Protocol != "" && !strings.HasPrefix(info.Protocol, "HSSH/1") {
		return &ConnectError{
			Target: target,
			Reason: fmt.Sprintf("host speaks %s but this client speaks %s",
				info.Protocol, protocol.Version),
			Hint: "Upgrade the host or use a matching client version.",
		}
	}

	// ---- WebSocket upgrade ----------------------------------------------
	lim := wsx.DefaultLimits()

	d := &wsx.Dialer{
		Timeout:     c.cfg.Timeout,
		Limits:      lim,
		Subprotocol: wsx.ProtocolSubprotocol,
	}
	if c.cfg.TLS {
		tlsCfg, err := wsx.BuildTLS(wsx.TLSOptions{
			CAFile:             c.cfg.CAFile,
			InsecureSkipVerify: c.cfg.Insecure,
			ServerName:         c.cfg.Host,
		})
		if err != nil {
			return &ConnectError{Target: target, Reason: err.Error(), Wrapped: err}
		}
		d.TLSConfig = tlsCfg
	}

	wsURL := toWSURL(c.cfg.URL)
	conn, resp, err := d.Dial(wsURL)
	if err != nil {
		return c.dialError(target, err, resp)
	}
	c.conn = conn

	// ---- Protocol hello --------------------------------------------------
	if err := c.sendControl(&protocol.HelloMsg{
		Type:     "hello",
		Protocol: protocol.Version,
		Client:   protocol.Name,
		Version:  protocol.VersionString,
		OS:       runtime.GOOS + "/" + runtime.GOARCH,
	}); err != nil {
		return c.fail(err)
	}

	// ---- Authentication --------------------------------------------------
	if err := c.authenticate(wsxClosePolicy, conn); err != nil {
		return c.fail(err)
	}

	c.log.Info("connected",
		logging.F("target", target),
		logging.F("host_version", info.Version),
		logging.F("tls", conn.IsTLS()),
	)
	return nil
}

// authenticate performs the credential exchange.
func (c *Client) authenticate(closeCode int, conn *wsx.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return c.fail(err)
	}
	// The server states its challenge first.
	frame, err := c.readFrame()
	if err != nil {
		return err
	}
	if frame.Op != protocol.MessageAuthResult {
		return c.fail(fmt.Errorf("expected an auth challenge, got %s", frame.Op))
	}
	var challenge protocol.AuthResultMsg
	if err := protocol.DecodeControl(frame, &challenge); err != nil {
		return c.fail(err)
	}

	cred := c.credential(challenge.Error)
	if err := c.sendControl(&protocol.AuthMsg{
		Type:     "auth",
		Method:   cred.Method,
		Password: cred.Password,
		Token:    cred.Token,
		Resume:   c.cfg.ResumeSession,
	}); err != nil {
		return c.fail(err)
	}

	frame, err = c.readFrame()
	if err != nil {
		return err
	}
	var res protocol.AuthResultMsg
	if err := protocol.DecodeControl(frame, &res); err != nil {
		return c.fail(err)
	}
	if frame.Op == protocol.MessageError || !res.OK {
		_ = conn.ClearReadDeadline()
		return c.fail(ErrAuthFailed)
	}
	_ = conn.ClearReadDeadline()
	return nil
}

// credential builds the auth material from flags, the environment, or an
// interactive prompt. A password is never taken from a URL.
func (c *Client) credential(challenge string) auth.Credential {
	switch {
	case c.cfg.Token != "":
		return auth.Credential{Method: auth.MethodToken, Token: c.cfg.Token}
	case c.cfg.Password != "":
		return auth.Credential{Method: auth.MethodPassword, Password: c.cfg.Password}
	}
	// HSSH_TOKEN / HSSH_PASSWORD let a user avoid the prompt (and avoid the
	// password appearing in shell history).
	if v := os.Getenv("HSSH_TOKEN"); v != "" {
		return auth.Credential{Method: auth.MethodToken, Token: v}
	}
	if v := os.Getenv("HSSH_PASSWORD"); v != "" {
		return auth.Credential{Method: auth.MethodPassword, Password: v}
	}
	if !strings.Contains(challenge, auth.MethodToken) {
		return auth.Credential{Method: auth.MethodPassword}
	}
	return auth.Credential{Method: auth.MethodToken}
}

// QuerySessions opens a short-lived connection and asks the host for its live
// session table. It never starts a terminal, so it is safe to run from another
// terminal while a session is in progress.
func (c *Client) QuerySessions() (*protocol.SessionsListMsg, error) {
	if c.conn == nil {
		return nil, ErrNotConnected
	}
	if err := c.sendControl(&protocol.SessionsRequestMsg{Type: "sessions_request"}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		frame, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		if frame.Op == protocol.MessageSessionsList {
			var msg protocol.SessionsListMsg
			if err := protocol.DecodeControl(frame, &msg); err != nil {
				return nil, err
			}
			return &msg, nil
		}
		if frame.Op == protocol.MessageError {
			var e protocol.ErrorMsg
			_ = protocol.DecodeControl(frame, &e)
			return nil, fmt.Errorf("%s: %s", e.Code, e.Message)
		}
	}
	return nil, errors.New("the host did not answer the session query in time")
}

// Start asks the server for a terminal, enters raw mode and runs the session
// until the shell exits or the user disconnects.
func (c *Client) Start(size terminal.Size) error {
	if c.conn == nil {
		return ErrNotConnected
	}

	if err := c.sendControl(&protocol.TerminalStartMsg{
		Type:        "terminal_start",
		Cols:        size.Cols,
		Rows:        size.Rows,
		Term:        c.termValue(),
		Cwd:         c.cfg.Cwd,
		ColorScheme: c.colorScheme(),
	}); err != nil {
		return c.fail(err)
	}

	// Enter raw mode only once the server has a PTY, so a failed connection
	// never leaves the user's terminal broken.
	state, err := terminal.MakeRaw(c.in)
	if err != nil {
		c.conn.CloseWith(wsxCloseInternal, "client terminal unavailable")
		return c.fail(fmt.Errorf("%w: %v", ErrTerminal, err))
	}
	c.term = state

	// Whatever happens from here, the terminal goes back the way it was.
	defer c.restoreTerminal()

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, signalWinch(), signalInterrupt(), signalTerminate())
	defer signal.Stop(sigs)

	c.wg.Add(2)
	go c.watchSize(sigs, size)
	go c.readLoop()

	// The keyboard read blocks, so it runs on its own goroutine and the caller
	// waits on whichever finishes first: the user (or the socket) ending the
	// session. A shell that exits while nobody is typing must still end the
	// session promptly.
	//
	// NOTE: this goroutine is deliberately NOT counted in c.wg. Its stdin
	// Read cannot be interrupted on shutdown, so it may stay blocked until
	// the process exits (e.g. remote shell died while the user types
	// nothing). Counting it caused "negative WaitGroup counter" panics on
	// every clean disconnect: watchSize + readLoop + writeLoop = 3 Dones
	// against Add(2). Start already synchronises with it via writeErr/closed,
	// and it never touches terminal state, so nothing waits on it.
	writeErr := make(chan error, 1)
	go func() {
		writeErr <- c.writeLoop(sigs)
	}()

	var runErr error
	select {
	case runErr = <-writeErr:
	case <-c.closed:
	}

	// Closing the socket unblocks the keyboard read's peer side and the reader,
	// so no goroutine can touch the terminal after it is restored.
	c.conn.Close()
	c.wg.Wait()
	// wg.Wait synchronises with readLoop, so these plain fields are safe here.
	if !c.gotInfo && c.earlyErr != "" {
		return errors.New("the host rejected the session: " + c.earlyErr)
	}
	return runErr
}

// writeLoop reads local keystrokes and forwards them to the server.
func (c *Client) writeLoop(sigs <-chan os.Signal) error {
	buf := make([]byte, 4096)
	for {
		select {
		case <-c.closed:
			return nil
		case sig := <-sigs:
			switch sig {
			case signalInterrupt(), signalTerminate():
				// The local terminal is in raw mode, so Ctrl+C arrives as a
				// byte rather than a signal. Treat a real SIGINT/SIGTERM
				// (kill -INT) as "disconnect cleanly".
				c.log.Debug("local signal", logging.F("signal", sig.String()))
				c.Disconnect("local signal")
				return nil
			}
		default:
		}

		n, err := c.in.Read(buf)
		if n > 0 {
			forward, disconnect := c.parser.Filter(buf[:n])
			if len(forward) > 0 {
				if err := c.conn.WriteBinary(protocol.EncodePayload(protocol.PayloadInput, forward)); err != nil {
					return c.fail(err)
				}
			}
			if disconnect {
				c.log.Info("disconnect sequence pressed")
				c.Disconnect("disconnect sequence")
				return nil
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			c.log.Debug("stdin closed", logging.F("reason", err.Error()))
			c.Disconnect("local input closed")
			return nil
		}
	}
}

// readLoop is the client -> nothing, server -> terminal direction.
func (c *Client) readLoop() {
	defer c.wg.Done()
	for {
		frame, err := c.readFrame()
		if err != nil {
			if !wsx.IsClosed(err) {
				c.log.Debug("read loop ended", logging.F("reason", err.Error()))
			}
			c.shutdown()
			return
		}
		switch frame.Op {
		case protocol.PayloadOutput:
			// Raw terminal bytes go straight to the local tty. No filtering,
			// no re-encoding: colours, cursor motion, alternate screen and
			// UTF-8 all render natively.
			if _, err := c.out.Write(frame.Data); err != nil {
				c.log.Debug("stdout write failed", logging.F("reason", err.Error()))
			}

		case protocol.MessageSessionInfo:
			var info protocol.SessionInfoMsg
			_ = protocol.DecodeControl(frame, &info)
			c.gotInfo = true
			c.log.Debug("session info", logging.F("session", shortID(info.Session)))

		case protocol.MessageTerminalExit:
			var msg protocol.TerminalExitMsg
			_ = protocol.DecodeControl(frame, &msg)
			select {
			case c.remoteExit <- msg:
			default:
			}
			// Give the final output a moment to drain before tearing down.
			time.Sleep(50 * time.Millisecond)
			c.shutdown()
			return

		case protocol.MessageError:
			var msg protocol.ErrorMsg
			_ = protocol.DecodeControl(frame, &msg)
			if c.earlyErr == "" && msg.Message != "" {
				c.earlyErr = msg.Message
			}
			c.log.Warn("server error",
				logging.F("code", msg.Code),
				logging.F("message", msg.Message))

		case protocol.MessageDisconnect:
			var msg protocol.DisconnectMsg
			_ = protocol.DecodeControl(frame, &msg)
			c.log.Info("server closed the session", logging.F("reason", msg.Reason))
			c.shutdown()
			return

		case protocol.MessagePing:
			var msg protocol.PingMsg
			_ = protocol.DecodeControl(frame, &msg)
			_ = c.sendControl(&protocol.PongMsg{Type: "pong", Seq: msg.Seq, TS: nowMillis()})

		case protocol.MessagePong:
			// Keepalive response; nothing to do.

		case protocol.MessageAuthResult:
			// Late auth frames are not expected here.

		default:
			c.log.Debug("unexpected frame", logging.F("type", frame.Op.String()))
		}
	}
}

// watchSize sends a resize whenever the local window changes, debounced so a
// drag of the terminal edge does not flood the socket.
func (c *Client) watchSize(sigs <-chan os.Signal, initial terminal.Size) {
	defer c.wg.Done()
	const debounce = 60 * time.Millisecond
	var last terminal.Size = initial
	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		select {
		case <-c.closed:
			return
		case <-sigs:
			if timer != nil {
				timer.Stop()
			}
			timer = time.NewTimer(debounce)
			timerC = timer.C
		case <-timerC:
			timerC = nil
			size, err := terminal.SizeOf(c.in)
			if err != nil || size.Cols == 0 || size.Rows == 0 {
				continue
			}
			if size == last {
				continue
			}
			last = size
			if err := c.sendControl(&protocol.TerminalResizeMsg{
				Type: "resize", Cols: size.Cols, Rows: size.Rows,
			}); err != nil {
				c.log.Debug("resize send failed", logging.F("reason", err.Error()))
				return
			}
		}
	}
}

// Disconnect closes the session cleanly: a disconnect message, a WebSocket
// close frame, then the socket.
func (c *Client) Disconnect(reason string) {
	_ = c.sendControl(&protocol.DisconnectMsg{Type: "disconnect", Reason: reason})
	_ = c.conn.WriteClose(wsxCloseNormal, reason)
	c.shutdown()
}

// Close is Disconnect with a forced, immediate teardown.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.CloseWith(wsxCloseAbnormal, "client exited")
	}
	c.shutdown()
}

func (c *Client) shutdown() {
	c.closeOnce.Do(func() { close(c.closed) })
}

func (c *Client) fail(err error) error {
	c.shutdown()
	return err
}

func (c *Client) restoreTerminal() {
	if c.term != nil {
		if err := c.term.Restore(); err != nil {
			c.log.Warn("terminal restore failed", logging.F("reason", err.Error()))
		}
		c.term = nil
	}
}

// Restore returns the local terminal to its original state. The CLI calls it
// from its signal and panic handlers; everything else goes through Start's
// defer.
func (c *Client) Restore() { c.restoreTerminal() }

// Wait blocks until the session is over and every client goroutine has
// finished, so no background write can touch the terminal after it is
// restored.
func (c *Client) Wait() {
	<-c.closed
	if c.conn != nil {
		c.conn.Close()
	}
	c.wg.Wait()
}

// ExitStatus returns the remote shell's exit status, if it has been reported.
func (c *Client) ExitStatus() (protocol.TerminalExitMsg, bool) {
	select {
	case st := <-c.remoteExit:
		return st, true
	default:
		return protocol.TerminalExitMsg{}, false
	}
}

func (c *Client) sendControl(msg any) error {
	if c.conn == nil {
		return ErrNotConnected
	}
	b, err := protocol.EncodeControl(msg)
	if err != nil {
		return err
	}
	return c.conn.WriteText(b)
}

func (c *Client) readFrame() (protocol.Frame, error) {
	raw, _, err := c.conn.ReadMessage()
	if err != nil {
		return protocol.Frame{}, wsx.NormaliseClose(err)
	}
	if len(raw) > protocol.MaxControlFrame {
		// A binary frame larger than the control limit is legitimate terminal
		// output, so only reject it when the opcode says control.
		if len(raw) > 0 && (protocol.OpCode(raw[0]) == protocol.PayloadOutput) {
			return protocol.Decode(raw)
		}
		return protocol.Frame{}, protocol.ErrFrameTooBig
	}
	return protocol.Decode(raw)
}

// discover performs the HTTP handshake against /health.
func (c *Client) discover(target string) (*HostInfo, error) {
	req, err := newHealthRequest(target)
	if err != nil {
		return nil, &ConnectError{Target: target, Reason: err.Error(), Wrapped: err}
	}
	resp, body, err := doRequest(req, c.cfg)
	if err != nil {
		return nil, c.dialError(target, err, nil)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, &ConnectError{
			Target: target,
			Reason: fmt.Sprintf("the host answered %s", resp.Status),
			Hint:   "Is this really an HSSH host? Check the URL and the port.",
		}
	}
	info := &HostInfo{}
	if err := decodeJSON(body, info); err != nil {
		return nil, &ConnectError{
			Target: target,
			Reason: "the host did not return a valid HSSH discovery document",
			Hint:   "Check whether something other than HSSH is listening on that port.",
		}
	}
	if info.Name != "" && !strings.EqualFold(info.Name, protocol.Name) {
		return nil, &ConnectError{
			Target: target,
			Reason: fmt.Sprintf("the service identifies itself as %q, not %q",
				info.Name, protocol.Name),
		}
	}
	return info, nil
}

// dialError turns a network failure into an actionable message.
func (c *Client) dialError(target string, err error, resp *http.Response) *ConnectError {
	ce := &ConnectError{Target: target, Wrapped: err}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		ce.Reason = fmt.Sprintf("host %q could not be resolved", dnsErr.Name)
		ce.Hint = "Check the hostname and your DNS."
		return ce
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			ce.Reason = "connection refused"
			ce.Hint = "Is the HSSH host running, and is the port correct?\n" +
				"  On the host:  hssh host --port=" + portOf(target)
			return ce
		}
		if errors.Is(opErr.Err, syscall.ETIMEDOUT) || os.IsTimeout(err) {
			ce.Reason = "connection timed out"
			ce.Hint = "A firewall between you and the host is probably dropping packets."
			return ce
		}
		ce.Reason = opErr.Err.Error()
		return ce
	}
	if x509Err, ok := err.(x509CertError); ok {
		ce.Reason = "TLS certificate verification failed: " + x509Err.Error()
		ce.Hint = "Point --ca at your CA bundle, or use --insecure for a lab host."
		return ce
	}
	if resp != nil {
		ce.Reason = fmt.Sprintf("the host answered %s", resp.Status)
		return ce
	}
	ce.Reason = err.Error()
	return ce
}

func portOf(target string) string {
	if u, err := parseTarget(target); err == nil {
		return u.Port()
	}
	return "8080"
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
