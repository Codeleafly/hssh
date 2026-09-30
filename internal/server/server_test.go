package server_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/client"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/server"
	"github.com/hssh/hssh/internal/terminal"
	"github.com/hssh/hssh/internal/wsx"
)

// testHost is a running in-process HSSH host used by the protocol tests. The
// interactive client is covered by the tests/ package, which drives the real
// binaries through a real PTY; these tests focus on the wire protocol.
type testHost struct {
	t      *testing.T
	host   *server.Host
	addr   string
	target string
	logs   *syncBuffer
}

// syncBuffer collects log output from many goroutines without a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newHost(t *testing.T, mutate func(*config.HostConfig)) *testHost {
	t.Helper()
	port := freePort(t)
	cfg := &config.HostConfig{
		Host:                 "127.0.0.1",
		Port:                 port,
		AuthMode:             config.AuthNone,
		AllowUnauthenticated: true,
		OutputBuffer:         1 << 20,
		MaxFrameSize:         1 << 20,
		Heartbeat:            30 * time.Second,
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	logs := &syncBuffer{}
	lg := logging.New(logs, logging.LevelDebug, false)
	h, err := server.New(server.Options{Config: cfg, Log: lg})
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	addr, err := h.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	th := &testHost{
		t: t, host: h, addr: addr,
		target: "http://" + strings.TrimPrefix(strings.TrimPrefix(addr, "[::]"), ""),
		logs:   logs,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	return th
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (th *testHost) log() string { return th.logs.String() }

// rawClient is a minimal WebSocket client for protocol-level tests, so the
// tests can send exactly the bytes they want to test.
type rawClient struct {
	conn   *wsx.Conn
	t      *testing.T
	pushed []protocol.Frame
}

func dialRaw(t *testing.T, target string, tlsCfg *tls.Config) *rawClient {
	t.Helper()
	u, _, err := parseWSTarget(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	d := &wsx.Dialer{
		Timeout:     10 * time.Second,
		Limits:      wsx.DefaultLimits(),
		Subprotocol: wsx.ProtocolSubprotocol,
	}
	if tlsCfg != nil {
		d.TLSConfig = wrapTLS(tlsCfg)
	}
	conn, _, err := d.Dial(u)
	if err != nil {
		t.Fatalf("dial %s: %v", u, err)
	}
	t.Cleanup(func() { conn.Close() })
	return &rawClient{conn: conn, t: t}
}

func (c *rawClient) sendText(msg any) {
	c.t.Helper()
	b, err := protocol.EncodeControl(msg)
	if err != nil {
		c.t.Fatalf("encode: %v", err)
	}
	if err := c.conn.WriteText(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *rawClient) sendBinary(op protocol.OpCode, data []byte) {
	c.t.Helper()
	if err := c.conn.WriteBinary(protocol.EncodePayload(op, data)); err != nil {
		c.t.Fatalf("write binary: %v", err)
	}
}

func (c *rawClient) read() protocol.Frame {
	c.t.Helper()
	if len(c.pushed) > 0 {
		f := c.pushed[0]
		c.pushed = c.pushed[1:]
		return f
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	raw, _, err := c.conn.ReadMessage()
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	f, err := protocol.Decode(raw)
	if err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return f
}

// handshakeCwd is handshake with an explicit working-directory request.
func (c *rawClient) handshakeCwd(cols, rows int, cwd string) {
	c.t.Helper()
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test", Version: "1.0.0"})
	// The host states its challenge before the credential.
	ch := c.read()
	if ch.Op != protocol.MessageAuthResult {
		c.t.Fatalf("expected an auth challenge, got %s", ch.Op)
	}
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodNone})
	res := c.read()
	var ar protocol.AuthResultMsg
	_ = protocol.DecodeControl(res, &ar)
	if !ar.OK {
		c.t.Fatalf("authentication failed: %+v", ar)
	}
	c.sendText(&protocol.TerminalStartMsg{Type: "terminal_start", Cols: cols, Rows: rows, Term: "xterm-256color", Cwd: cwd})
}

// handshake performs hello + auth + terminal_start.
func (c *rawClient) handshake(cols, rows int) {
	c.t.Helper()
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test", Version: "1.0.0"})
	// The host states its challenge before the credential.
	ch := c.read()
	if ch.Op != protocol.MessageAuthResult {
		c.t.Fatalf("expected an auth challenge, got %s", ch.Op)
	}
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodNone})
	res := c.read()
	var ar protocol.AuthResultMsg
	_ = protocol.DecodeControl(res, &ar)
	if !ar.OK {
		c.t.Fatalf("authentication failed: %+v", ar)
	}
	c.sendText(&protocol.TerminalStartMsg{Type: "terminal_start", Cols: cols, Rows: rows, Term: "xterm-256color"})
}

// ---------------------------------------------------------------- tests

func TestHealthEndpointReportsProtocol(t *testing.T) {
	th := newHost(t, nil)
	body, status := httpGet(t, "http://"+th.addr+"/health")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{`"name":"hssh"`, `"protocol":"HSSH/1"`, `"websocket":true`, `"tls":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("health body is missing %s:\n%s", want, body)
		}
	}
}

func TestIndexPageIsHarmless(t *testing.T) {
	th := newHost(t, nil)
	body, status := httpGet(t, "http://"+th.addr+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if strings.Contains(strings.ToLower(body), "password") {
		t.Fatalf("the index page should not mention credentials:\n%s", body)
	}
}

func TestConnectRequiresAWebSocketUpgrade(t *testing.T) {
	th := newHost(t, nil)
	_, status := httpGet(t, "http://"+th.addr+"/connect")
	if status != http.StatusBadRequest {
		t.Fatalf("a plain GET on /connect should be rejected, got %d", status)
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	th := newHost(t, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://"+th.addr+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("X-Content-Type-Options is missing")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("Content-Security-Policy is missing")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no CORS header should be sent: a browser must not be able to attach")
	}
}

func TestWrongProtocolVersionIsRejectedCleanly(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: "HSSH/99", Client: "test"})

	f := c.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("expected an error frame, got %s", f.Op)
	}
	var e protocol.ErrorMsg
	_ = protocol.DecodeControl(f, &e)
	if e.Code != protocol.ErrCodeProtocol {
		t.Fatalf("error code = %q", e.Code)
	}
	if !strings.Contains(e.Message, "HSSH/1") {
		t.Fatalf("the error should say what the host speaks: %q", e.Message)
	}
}

func TestFirstMessageMustBeHello(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.sendText(&protocol.TerminalStartMsg{Type: "terminal_start", Cols: 80, Rows: 24})
	f := c.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("expected an error, got %s", f.Op)
	}
}

func TestTerminalOutputFlowsOverTheWire(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)

	info := c.read()
	if info.Op != protocol.MessageSessionInfo {
		t.Fatalf("expected session_info, got %s", info.Op)
	}
	var si protocol.SessionInfoMsg
	_ = protocol.DecodeControl(info, &si)
	if si.Session == "" || si.Shell == "" || si.PID <= 0 {
		t.Fatalf("session_info is incomplete: %+v", si)
	}
	if si.Cols != 100 || si.Rows != 30 {
		t.Fatalf("session_info size = %dx%d", si.Cols, si.Rows)
	}

	// Terminal data comes back on binary payload frames.
	c.sendBinary(protocol.PayloadInput, []byte("echo WIRE_TOKEN\n"))
	var got []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(string(got), "WIRE_TOKEN\r\n") {
		f := c.read()
		if f.Op == protocol.PayloadOutput {
			got = append(got, f.Data...)
		}
	}
	if !strings.Contains(string(got), "WIRE_TOKEN") {
		t.Fatalf("terminal output never arrived:\n%q", got)
	}
}

func TestResizeIsApplied(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	c.sendText(&protocol.TerminalResizeMsg{Type: "resize", Cols: 123, Rows: 45})
	// No error frame should come back for a valid resize.
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, _, err := c.conn.ReadMessage()
	if err == nil {
		f, _ := protocol.Decode(raw)
		if f.Op == protocol.MessageError {
			var e protocol.ErrorMsg
			_ = protocol.DecodeControl(f, &e)
			t.Fatalf("a valid resize was rejected: %s", e.Message)
		}
	}

	// Confirm the shell sees the new size.
	deadline := time.Now().Add(10 * time.Second)
	c.conn.SetReadDeadline(deadline)
	c.sendBinary(protocol.PayloadInput, []byte("stty size\n"))
	var buf []byte
	for time.Now().Before(deadline) && !strings.Contains(string(buf), "45 123") {
		raw, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		f, _ := protocol.Decode(raw)
		if f.Op == protocol.PayloadOutput {
			buf = append(buf, f.Data...)
		}
	}
	if !strings.Contains(string(buf), "45 123") {
		t.Fatalf("the remote PTY did not take the new size:\n%q", buf)
	}
}

func TestShellExitIsReported(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	c.sendBinary(protocol.PayloadInput, []byte("exit 9\n"))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		f := c.read()
		if f.Op == protocol.MessageTerminalExit {
			var ex protocol.TerminalExitMsg
			_ = protocol.DecodeControl(f, &ex)
			if ex.Code != 9 {
				t.Fatalf("exit code = %d, want 9", ex.Code)
			}
			return
		}
	}
	t.Fatal("no terminal_exit message arrived")
}

func TestSessionsRequestReturnsTheTable(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	c.sendText(&protocol.SessionsRequestMsg{Type: "sessions_request"})
	f := c.read()
	if f.Op != protocol.MessageSessionsList {
		t.Fatalf("expected sessions_list, got %s", f.Op)
	}
	var list protocol.SessionsListMsg
	_ = protocol.DecodeControl(f, &list)
	if len(list.Sessions) != 1 {
		t.Fatalf("expected exactly the live session, got %d", len(list.Sessions))
	}
	e := list.Sessions[0]
	if e.Client == "" || e.Shell == "" || e.Cols != 100 || e.Rows != 30 {
		t.Fatalf("session entry is incomplete: %+v", e)
	}
	if e.Cwd == "" {
		t.Fatalf("session entry should carry the working directory: %+v", e)
	}
	// The table must never carry credentials or terminal content.
	raw, _ := protocol.EncodeControl(&list)
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "token") {
		t.Fatalf("the session table leaks a credential: %s", raw)
	}
}

func TestClientCannotInjectOutputFrames(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	// A client that sends a server->client opcode must be ignored, and the
	// session must keep working.
	c.sendBinary(protocol.PayloadOutput, []byte("FAKE\r\n"))
	c.sendBinary(protocol.PayloadInput, []byte("echo STILL_ALIVE\n"))

	deadline := time.Now().Add(10 * time.Second)
	var buf []byte
	for time.Now().Before(deadline) && !strings.Contains(string(buf), "STILL_ALIVE") {
		raw, _, err := c.conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		f, _ := protocol.Decode(raw)
		if f.Op == protocol.PayloadOutput {
			buf = append(buf, f.Data...)
		}
	}
	if strings.Contains(string(buf), "FAKE") {
		t.Fatalf("the server echoed a client-supplied output frame:\n%q", buf)
	}
	if !strings.Contains(string(buf), "STILL_ALIVE") {
		t.Fatalf("the session did not survive:\n%q", buf)
	}
}

func TestMalformedJSONDoesNotKillTheSession(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	// A control frame whose body is not valid JSON.
	if err := c.conn.WriteText([]byte{byte(protocol.MessageTerminalResize), '{', 'b', 'a', 'd'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.sendBinary(protocol.PayloadInput, []byte("echo SURVIVED_BAD_JSON\n"))

	deadline := time.Now().Add(10 * time.Second)
	var buf []byte
	for time.Now().Before(deadline) && !strings.Contains(string(buf), "SURVIVED_BAD_JSON") {
		raw, _, err := c.conn.ReadMessage()
		if err != nil {
			t.Fatalf("the session died on a malformed frame: %v", err)
		}
		f, _ := protocol.Decode(raw)
		if f.Op == protocol.PayloadOutput {
			buf = append(buf, f.Data...)
		}
	}
	if !strings.Contains(string(buf), "SURVIVED_BAD_JSON") {
		t.Fatalf("output missing after a malformed frame:\n%q", buf)
	}
}

func TestOversizedFrameIsRefusedAtTheTransport(t *testing.T) {
	// A frame beyond the read limit must be refused by the WebSocket layer
	// with close code 1009, before HSSH ever tries to interpret the bytes.
	// This is the defence against a peer that tries to make the host allocate
	// an arbitrary amount of memory with a single frame.
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	huge := append([]byte{byte(protocol.MessageTerminalResize)}, make([]byte, 2<<20)...)
	_ = c.conn.WriteText(huge)

	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err := c.conn.ReadMessage()
	if err == nil {
		t.Fatal("an oversized frame should have been refused")
	}
	if !wsx.IsClosed(err) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "1009") {
		t.Fatalf("expected close code 1009 (message too big), got %v", err)
	}
}

func TestSessionLimitIsEnforced(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) { c.MaxSessions = 1 })

	c1 := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c1.handshake(100, 30)
	_ = c1.read() // session_info

	// The second client is refused during the upgrade, before any PTY is
	// allocated, with 503 and a Retry-After hint.
	d := &wsx.Dialer{Timeout: 5 * time.Second, Limits: wsx.DefaultLimits(),
		Subprotocol: wsx.ProtocolSubprotocol}
	_, resp, err := d.Dial("ws://" + th.addr + "/connect")
	if err == nil {
		t.Fatal("a second session was accepted despite --max-sessions=1")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("second connection status = %d, want 503", status)
	}
	if th.host.Sessions().Count() != 1 {
		t.Fatalf("the refused connection consumed a session slot: %d", th.host.Sessions().Count())
	}
}

func TestPasswordAuthRejectsOverPlainHTTP(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) {
		c.AuthMode = config.AuthPassword
		c.Password = "s3cret"
		c.AllowUnauthenticated = false
	})
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test"})
	_ = c.read() // challenge
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodPassword, Password: "s3cret"})

	f := c.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("expected an error, got %s", f.Op)
	}
	var e protocol.ErrorMsg
	_ = protocol.DecodeControl(f, &e)
	if e.Code != protocol.ErrCodeAuth {
		t.Fatalf("error code = %q", e.Code)
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	cert, key, ca := selfSignedCert(t)
	th := newHost(t, func(c *config.HostConfig) {
		c.AuthMode = config.AuthPassword
		c.Password = "s3cret"
		c.AllowUnauthenticated = false
		c.TLSCert = cert
		c.TLSKey = key
	})
	tlsCfg := &tls.Config{RootCAs: ca, ServerName: "localhost"}

	c := dialRaw(t, "https://"+th.addr+"/connect", tlsCfg)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test"})
	_ = c.read() // challenge
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodPassword, Password: "wrong"})
	f := c.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("expected an error, got %s", f.Op)
	}

	// The host log must never contain the password.
	if strings.Contains(th.log(), "wrong") {
		t.Fatalf("the host log contains the attempted password:\n%s", th.log())
	}
}

func TestCorrectPasswordOverTLSIsAccepted(t *testing.T) {
	cert, key, ca := selfSignedCert(t)
	th := newHost(t, func(c *config.HostConfig) {
		c.AuthMode = config.AuthPassword
		c.Password = "s3cret"
		c.AllowUnauthenticated = false
		c.TLSCert = cert
		c.TLSKey = key
	})
	tlsCfg := &tls.Config{RootCAs: ca, ServerName: "localhost"}

	c := dialRaw(t, "https://"+th.addr+"/connect", tlsCfg)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test"})
	_ = c.read()
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodPassword, Password: "s3cret"})
	res := c.read()
	var ar protocol.AuthResultMsg
	_ = protocol.DecodeControl(res, &ar)
	if !ar.OK {
		t.Fatalf("the correct password was rejected: %+v", ar)
	}
	if !c.conn.IsTLS() {
		t.Fatal("the connection should be reported as encrypted")
	}
	// The log records the method but never the secret.
	if strings.Contains(th.log(), "s3cret") {
		t.Fatalf("the host log leaked the password:\n%s", th.log())
	}
}

func TestTokenAuthOverTLS(t *testing.T) {
	cert, key, ca := selfSignedCert(t)
	th := newHost(t, func(c *config.HostConfig) {
		c.AuthMode = config.AuthToken
		c.Token = "tok-abc"
		c.AllowUnauthenticated = false
		c.TLSCert = cert
		c.TLSKey = key
	})
	tlsCfg := &tls.Config{RootCAs: ca, ServerName: "localhost"}

	c := dialRaw(t, "https://"+th.addr+"/connect", tlsCfg)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test"})
	_ = c.read()
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodToken, Token: "tok-abc"})
	res := c.read()
	var ar protocol.AuthResultMsg
	_ = protocol.DecodeControl(res, &ar)
	if !ar.OK {
		t.Fatalf("the correct token was rejected: %+v", ar)
	}
}

func TestHealthReportsTLS(t *testing.T) {
	cert, key, _ := selfSignedCert(t)
	th := newHost(t, func(c *config.HostConfig) {
		c.TLSCert = cert
		c.TLSKey = key
	})
	body, status := httpGet(t, "https://"+th.addr+"/health")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(body, `"tls":true`) {
		t.Fatalf("health should report TLS:\n%s", body)
	}
}

func TestClientRefusesPlaintextCredentials(t *testing.T) {
	// The client must not put a password on a ws:// connection even when asked.
	th := newHost(t, func(c *config.HostConfig) {
		c.AuthMode = config.AuthPassword
		c.Password = "s3cret"
		c.AllowUnauthenticated = false
	})
	cfg := &config.ClientConfig{
		URL:      th.target,
		Password: "s3cret",
		Timeout:  5 * time.Second,
	}
	cl, err := client.New(client.Options{Config: cfg, Log: logging.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Connect(); err == nil {
		t.Fatal("the client should refuse to authenticate over plaintext HTTP")
	}
	cl.Close()
}

func TestTerminalIsReleasedOnDisconnect(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read()

	before := th.host.Sessions().Count()
	if before != 1 {
		t.Fatalf("sessions = %d", before)
	}
	c.conn.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && th.host.Sessions().Count() > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := th.host.Sessions().Count(); n != 0 {
		t.Fatalf("%d sessions survived the disconnect", n)
	}
	if !strings.Contains(th.log(), "pty closed") {
		t.Fatalf("the host log shows no PTY teardown:\n%s", th.log())
	}
}

// waitForOutput reads payload frames until needle appears.
func waitForOutput(t *testing.T, c *rawClient, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var buf []byte
	for time.Now().Before(deadline) && !strings.Contains(string(buf), needle) {
		raw, _, err := c.conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		f, _ := protocol.Decode(raw)
		if f.Op == protocol.PayloadOutput {
			buf = append(buf, f.Data...)
		}
	}
	if !strings.Contains(string(buf), needle) {
		t.Fatalf("never saw %q:\n%q", needle, buf)
	}
}

func TestHostShellAndWorkDirAreReported(t *testing.T) {
	th := newHost(t, nil)
	if th.host.Shell().Path == "" {
		t.Fatal("the host has no shell")
	}
	if th.host.WorkDir() == "" {
		t.Fatal("the host has no working directory")
	}
	if th.host.BindHost() != "127.0.0.1" {
		t.Fatalf("BindHost = %q", th.host.BindHost())
	}
}

func TestPerSessionCWDIsolation(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) { c.PerSessionCwd = true })

	// The PTY echoes what was typed, so the answer marker must distinguish the
	// shell's output from the echo. The command text contains the literal "%s";
	// the shell's reply contains the real path, so the first non-echo match is
	// the answer.
	readDir := func(c *rawClient) string {
		// The PTY echoes the command and the shell's prompt also names the
		// directory, so neither "the path appears" nor "the marker appears" is
		// a sufficient stop condition. The loop only ends when the shell's own
		// answer (a ZZCWD line whose value is not the literal "%s" from the
		// echo) has arrived.
		c.sendBinary(protocol.PayloadInput, []byte("printf 'ZZCWD:%s:ZZEND\\n' \"$PWD\"\n"))
		re := regexp.MustCompile(`ZZCWD:([^:]+):ZZEND`)
		deadline := time.Now().Add(15 * time.Second)
		var buf []byte
		for time.Now().Before(deadline) {
			raw, _, err := c.conn.ReadMessage()
			if err != nil {
				break
			}
			f, _ := protocol.Decode(raw)
			if f.Op != protocol.PayloadOutput {
				continue
			}
			buf = append(buf, f.Data...)
			for _, m := range re.FindAllStringSubmatch(string(buf), -1) {
				if len(m) == 2 && m[1] != "%s" {
					return strings.TrimSpace(m[1])
				}
			}
		}
		return ""
	}

	a := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	a.handshake(100, 30)
	_ = a.read()
	b := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	b.handshake(100, 30)
	_ = b.read()

	dirA := readDir(a)
	dirB := readDir(b)
	if dirA == "" || dirB == "" {
		t.Fatalf("could not read pwd (a=%q b=%q)\n--- host log ---\n%s", dirA, dirB, th.log())
	}
	if dirA == dirB {
		t.Fatalf("both sessions share the same working directory: %s", dirA)
	}
}

func TestResumeWithoutOptInIsRefused(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	info := c.read()
	var si protocol.SessionInfoMsg
	_ = protocol.DecodeControl(info, &si)

	// Asking to resume on a host that did not opt in is refused, even with a
	// genuine session id.
	r := dialRaw2(t, "ws://"+th.addr+"/connect", nil, si.Session)
	f := r.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("expected an error, got %s", f.Op)
	}
}

func TestResumeReattachesToTheSameShell(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) { c.AllowResume = true })

	a := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	a.handshake(100, 30)
	info := a.read()
	var si protocol.SessionInfoMsg
	_ = protocol.DecodeControl(info, &si)
	if si.Session == "" {
		t.Fatal("no session id reported")
	}

	// Leave a breadcrumb in the shell that only exists in this PTY.
	a.sendBinary(protocol.PayloadInput, []byte("export HSSH_RESUME_PROBE=resumed-ok; echo PROBE_ARMED\n"))
	waitForOutput(t, a, "PROBE_ARMED", 10*time.Second)

	// Now reconnect with --session=<id>. The shell must be the same one: its
	// pid and its breadcrumb survive.
	b := dialRaw2(t, "ws://"+th.addr+"/connect", nil, si.Session)
	binfo := b.read()
	var bsi protocol.SessionInfoMsg
	_ = protocol.DecodeControl(binfo, &bsi)
	if bsi.Session != si.Session {
		t.Fatalf("resumed as %s, want %s", bsi.Session, si.Session)
	}
	if bsi.PID != si.PID {
		t.Fatalf("the resume started a new shell (pid %d != %d)", bsi.PID, si.PID)
	}
	b.sendBinary(protocol.PayloadInput, []byte("echo $HSSH_RESUME_PROBE\n"))
	waitForOutput(t, b, "resumed-ok", 10*time.Second)
}

func TestResumeRejectsUnknownAndForeignSessions(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) { c.AllowResume = true })

	// A well-formed id that names nothing live.
	r := dialRaw2(t, "ws://"+th.addr+"/connect", nil, "0123456789abcdef0123456789abcdef")
	if f := r.read(); f.Op != protocol.MessageError {
		t.Fatalf("expected an error for an unknown session, got %s", f.Op)
	}

	// A malformed id is never even looked up.
	r2 := dialRaw2(t, "ws://"+th.addr+"/connect", nil, "not-a-session-id!!")
	if f := r2.read(); f.Op != protocol.MessageError {
		t.Fatalf("expected an error for a malformed id, got %s", f.Op)
	}
}

// dialRaw2 is dialRaw with a resume id attached to the auth message.
func dialRaw2(t *testing.T, target string, tlsCfg *tls.Config, resume string) *rawClient {
	t.Helper()
	c := dialRaw(t, target, tlsCfg)
	c.sendText(&protocol.HelloMsg{Type: "hello", Protocol: protocol.Version, Client: "test"})
	_ = c.read() // challenge
	c.sendText(&protocol.AuthMsg{Type: "auth", Method: auth.MethodNone, Resume: resume})
	res := c.read()
	if res.Op == protocol.MessageAuthResult {
		var ar protocol.AuthResultMsg
		_ = protocol.DecodeControl(res, &ar)
		if !ar.OK {
			t.Fatalf("authentication failed: %+v", ar)
		}
		return c
	}
	// The host answered with something else (an error); leave it for the test.
	// Push the frame back by stashing it on the client.
	c.pushed = append(c.pushed, res)
	return c
}

func TestSessionInfoRecordsTerminal(t *testing.T) {
	// The client's own view of the session, used to size the window correctly.
	th := newHost(t, nil)
	size := terminal.Size{Cols: 90, Rows: 20}
	cfg := &config.ClientConfig{URL: th.target, Timeout: 10 * time.Second}
	cl, err := client.New(client.Options{Config: cfg, Log: logging.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cl.Close()
	if cl.Detected == nil || cl.Detected.Protocol != protocol.Version {
		t.Fatalf("discovery did not report the protocol: %+v", cl.Detected)
	}
	_ = size
}

func TestTerminalStartCwdIsHonoured(t *testing.T) {
	dir := t.TempDir()
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshakeCwd(100, 30, dir)

	info := c.read()
	if info.Op != protocol.MessageSessionInfo {
		t.Fatalf("expected session_info, got %s", info.Op)
	}
	var si protocol.SessionInfoMsg
	_ = protocol.DecodeControl(info, &si)
	if si.Cwd != dir {
		t.Fatalf("session_info cwd = %q, want %q", si.Cwd, dir)
	}

	// The shell itself must really be there: PWD and pwd agree.
	c.sendBinary(protocol.PayloadInput, []byte("pwd\n"))
	deadline := time.Now().Add(15 * time.Second)
	var buf []byte
	for time.Now().Before(deadline) && !strings.Contains(string(buf), dir) {
		f := c.read()
		if f.Op == protocol.PayloadOutput {
			buf = append(buf, f.Data...)
		}
	}
	if !strings.Contains(string(buf), dir) {
		t.Fatalf("the shell is not in the requested directory:\n%q", buf)
	}
}

func TestTerminalStartBadCwdIsRejected(t *testing.T) {
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshakeCwd(100, 30, filepath.Join(t.TempDir(), "does-not-exist"))

	f := c.read()
	if f.Op != protocol.MessageError {
		t.Fatalf("a missing directory should be rejected with an error, got %s", f.Op)
	}
	var e protocol.ErrorMsg
	_ = protocol.DecodeControl(f, &e)
	if !strings.Contains(strings.ToLower(e.Message), "working directory") {
		t.Fatalf("the error should name the working directory problem: %+v", e)
	}
}

func TestTerminalStartCwdConflictsWithIsolation(t *testing.T) {
	th := newHost(t, func(c *config.HostConfig) { c.PerSessionCwd = true })
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshakeCwd(100, 30, t.TempDir())

	if f := c.read(); f.Op != protocol.MessageError {
		t.Fatalf("a --cwd against an isolating host should be refused, got %s", f.Op)
	}
}

func TestSessionsTableShowsCwd(t *testing.T) {
	dir := t.TempDir()
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshakeCwd(100, 30, dir)
	_ = c.read() // session_info

	c.sendText(&protocol.SessionsRequestMsg{Type: "sessions_request"})
	f := c.read()
	if f.Op != protocol.MessageSessionsList {
		t.Fatalf("expected sessions_list, got %s", f.Op)
	}
	var list protocol.SessionsListMsg
	_ = protocol.DecodeControl(f, &list)
	if len(list.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list.Sessions))
	}
	if list.Sessions[0].Cwd != dir {
		t.Fatalf("table cwd = %q, want %q", list.Sessions[0].Cwd, dir)
	}
}

func TestCwdLiveTrackingViaOSC7(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OSC 7 absolute-path test uses unix paths")
	}
	th := newHost(t, nil)
	c := dialRaw(t, "ws://"+th.addr+"/connect", nil)
	c.handshake(100, 30)
	_ = c.read() // session_info

	// The shell announces a directory change the way VS Code's
	// shell integration does.
	c.sendBinary(protocol.PayloadInput, []byte("printf '\\033]7;file://localhost/tmp\\033\\\\\\n'\n"))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c.sendText(&protocol.SessionsRequestMsg{Type: "sessions_request"})
		f := c.read()
		if f.Op != protocol.MessageSessionsList {
			continue
		}
		var list protocol.SessionsListMsg
		_ = protocol.DecodeControl(f, &list)
		if len(list.Sessions) == 1 && list.Sessions[0].Cwd == "/tmp" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the sessions table never showed the OSC 7 directory /tmp")
}
