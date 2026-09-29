// Package wsx wraps gorilla/websocket with the hardening HSSH needs: explicit
// size limits, origin checking, negotiated subprotocol, and a reader that
// distinguishes a normal close from a dead peer.
package wsx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Limits bounds everything a peer can push at us.
type Limits struct {
	// MaxFrameBytes is the largest single message accepted.
	MaxFrameBytes int64
	// ReadBufferSize / WriteBufferSize are per-connection buffers.
	ReadBufferSize  int
	WriteBufferSize int
	// MaxPendingPings bounds the ping queue.
	MaxPendingPings int
}

// DefaultLimits are conservative and appropriate for a terminal.
func DefaultLimits() Limits {
	return Limits{
		MaxFrameBytes:   1 << 20, // 1 MiB
		ReadBufferSize:  32 << 10,
		WriteBufferSize: 32 << 10,
		MaxPendingPings: 64,
	}
}

// Conn is a WebSocket connection guarded by a write mutex. Gorilla allows only
// one concurrent writer, and the HSSH server writes from both the PTY pump and
// control-message handlers, so serialisation is mandatory, not optional.
type Conn struct {
	ws   *websocket.Conn
	lim  Limits
	wmu  sync.Mutex
	rmu  sync.Mutex
	once sync.Once
}

// CloseWith sends a close frame with the given code and reason.
func (c *Conn) CloseWith(code int, reason string) {
	c.once.Do(func() {
		deadline := time.Now().Add(2 * time.Second)
		c.wmu.Lock()
		_ = c.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(code, reason), deadline)
		c.wmu.Unlock()
		_ = c.ws.Close()
	})
}

// Close drops the connection without a handshake.
func (c *Conn) Close() {
	c.once.Do(func() { _ = c.ws.Close() })
}

// RemoteAddr is the peer address, used for session bookkeeping.
func (c *Conn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

// LocalAddr is our address.
func (c *Conn) LocalAddr() net.Addr { return c.ws.LocalAddr() }

// Underlying exposes the raw connection, used for TLS state inspection.
func (c *Conn) Underlying() *websocket.Conn { return c.ws }

// NetConn returns the network connection carrying the WebSocket.
func (c *Conn) NetConn() net.Conn { return c.ws.NetConn() }

// NewConn wraps an upgraded gorilla connection with HSSH's limits applied.
func NewConn(ws *websocket.Conn, lim Limits) *Conn {
	c := &Conn{ws: ws, lim: lim}
	c.SetReadLimit(lim.MaxFrameBytes)
	return c
}

// IsTLS reports whether the connection is encrypted. This is the single
// source of truth for "may I send a password", so it is derived from the
// actual socket rather than from what the user typed.
func (c *Conn) IsTLS() bool {
	_, ok := c.ws.NetConn().(*tls.Conn)
	return ok
}

// SetReadLimit sets the maximum message size.
func (c *Conn) SetReadLimit(n int64) { c.ws.SetReadLimit(n) }

// SetReadDeadline bounds how long the next ReadMessage may block. A zero time
// clears the deadline.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

// SetPongHandler installs the keepalive handler and returns a channel that is
// signalled on every pong.
func (c *Conn) SetPongHandler(sig chan<- struct{}) {
	c.ws.SetPongHandler(func(string) error {
		select {
		case sig <- struct{}{}:
		default:
		}
		return nil
	})
}

// writeFrame is the single writer path: gorilla permits exactly one
// concurrent writer, and HSSH writes from the PTY pump, the control handler
// and the heartbeat at the same time.
func (c *Conn) writeFrame(kind int, b []byte, timeout time.Duration) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(timeout))
	err := c.ws.WriteMessage(kind, b)
	return err
}

// WriteBinary sends an opaque binary frame.
func (c *Conn) WriteBinary(b []byte) error {
	return c.writeFrame(websocket.BinaryMessage, b, 10*time.Second)
}

// WriteText sends a text frame.
func (c *Conn) WriteText(b []byte) error {
	return c.writeFrame(websocket.TextMessage, b, 10*time.Second)
}

// WritePing sends a protocol-level ping, which is cheaper than an application
// level one and keeps proxies from dropping an idle connection.
func (c *Conn) WritePing(payload []byte) error {
	return c.writeFrame(websocket.PingMessage, payload, 5*time.Second)
}

// WriteClose sends a close frame with an explicit code and reason.
func (c *Conn) WriteClose(code int, reason string) error {
	return c.writeFrame(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason), 2*time.Second)
}

// ReadMessage blocks for the next message. binary is true for BinaryMessage.
func (c *Conn) ReadMessage() (data []byte, binary bool, err error) {
	mt, data, err := c.ws.ReadMessage()
	if err != nil {
		return nil, false, err
	}
	return data, mt == websocket.BinaryMessage, nil
}

// ReadTimeout reads with a deadline. A timeout is reported as net.Error with
// Timeout()==true so the caller can distinguish it from a dead peer.
func (c *Conn) ReadTimeout(deadline time.Time) ([]byte, bool, error) {
	if err := c.ws.SetReadDeadline(deadline); err != nil {
		return nil, false, err
	}
	mt, data, err := c.ws.ReadMessage()
	if err != nil {
		return nil, false, err
	}
	return data, mt == websocket.BinaryMessage, nil
}

// ClearReadDeadline removes any read deadline.
func (c *Conn) ClearReadDeadline() error { return c.ws.SetReadDeadline(time.Time{}) }

// ErrClosedNormally is returned when the peer performed a clean close.
var ErrClosedNormally = errors.New("websocket: closed by peer")

// NormaliseClose converts a gorilla close error into a friendly sentinel.
func NormaliseClose(err error) error {
	if err == nil {
		return nil
	}
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	) {
		return ErrClosedNormally
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrClosedNormally
	}
	return err
}

// IsClosed reports whether err represents a closed or dead connection.
func IsClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrClosedNormally) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return websocket.IsCloseError(err,
		websocket.CloseNormalClosure, websocket.CloseGoingAway,
		websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived,
		// A frame the peer was not allowed to send, or a server-side failure,
		// also ends the connection for good.
		websocket.CloseMessageTooBig, websocket.CloseInternalServerErr)
}

// IsTimeout reports whether err is a read/write deadline expiry.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Upgrader builds a websocket.Upgrader with HSSH's defaults.
//
// allowedOrigins performs Host/Origin validation. An empty list means "no
// browser is in scope": Origin is only checked when the client actually sends
// one, and non-browser clients (the HSSH CLI) never do. HSSH v1 has no browser
// client, so CSRF-style cross-site WebSocket hijacking is not reachable.
func Upgrader(lim Limits, checkOrigin func(*http.Request) bool) *websocket.Upgrader {
	up := &websocket.Upgrader{
		HandshakeTimeout:  15 * time.Second,
		ReadBufferSize:    lim.ReadBufferSize,
		WriteBufferSize:   lim.WriteBufferSize,
		EnableCompression: false, // terminal data is high entropy; deflate hurts
		Subprotocols:      []string{ProtocolSubprotocol},
		CheckOrigin: func(r *http.Request) bool {
			if checkOrigin != nil {
				return checkOrigin(r)
			}
			return DefaultOriginCheck(r)
		},
	}
	return up
}

// DefaultOriginCheck accepts requests with no Origin (which is what the HSSH
// CLI sends) and, when an Origin is present, requires it to match the Host
// header.
//
// HSSH v1 has no browser client and serves no CORS headers, so a cross-site
// WebSocket is not reachable through normal means. This check closes the
// remaining DNS-rebinding shape: a page that resolves its own name to the HSSH
// host would still send a matching Host but a foreign Origin.
func DefaultOriginCheck(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := parseOriginURL(origin)
	if err != nil {
		return false
	}
	return equalAuthority(u.Host, r.Host, defaultPortForScheme(u.Scheme))
}

// DialOptions configures the client-side handshake.
type DialOptions struct {
	Header        http.Header
	HandshakeTO   time.Duration
	MaxFrameBytes int64
	Subprotocol   string
	// TLSConfig is applied by the caller through the underlying dialer.
}

// Dialer dials a HSSH WebSocket endpoint.
type Dialer struct {
	NetDial     func(network, addr string) (net.Conn, error)
	TLSConfig   *ClientTLS
	Timeout     time.Duration
	Header      http.Header
	Limits      Limits
	Subprotocol string
}

// Dial performs the HTTP Upgrade handshake against rawURL (ws:// or wss://).
func (d *Dialer) Dial(rawURL string) (*Conn, *http.Response, error) {
	u, err := parseWSURL(rawURL)
	if err != nil {
		return nil, nil, err
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout:  d.Timeout,
		ReadBufferSize:    d.Limits.ReadBufferSize,
		WriteBufferSize:   d.Limits.WriteBufferSize,
		EnableCompression: false,
		Subprotocols:      []string{d.subprotocol()},
	}
	if d.NetDial != nil {
		dialer.NetDialContext = nil
		dialer.NetDial = d.NetDial
	}
	if d.TLSConfig != nil {
		dialer.TLSClientConfig = d.TLSConfig.Config()
	}

	hdr := d.Header
	if hdr == nil {
		hdr = http.Header{}
	}
	ws, resp, err := dialer.Dial(u.String(), hdr)
	if err != nil {
		return nil, resp, fmt.Errorf("websocket upgrade failed: %w", err)
	}
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		ws.Close()
		return nil, resp, fmt.Errorf("websocket upgrade failed: unexpected status %d", resp.StatusCode)
	}
	c := &Conn{ws: ws, lim: d.Limits}
	c.SetReadLimit(d.Limits.MaxFrameBytes)
	return c, resp, nil
}

func (d *Dialer) subprotocol() string {
	if d.Subprotocol != "" {
		return d.Subprotocol
	}
	return ProtocolSubprotocol
}
