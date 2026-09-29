package protocol

import "time"

// Message is embedded in every control message. Type is the wire name and is
// the single source of truth for the frame opcode.
type Message struct {
	Type string `json:"type"`
}

// HelloMsg is the first message in both directions. It negotiates the protocol
// version and advertises client capabilities.
type HelloMsg struct {
	Type     string   `json:"type"` // "hello"
	Protocol string   `json:"protocol"`
	Client   string   `json:"client"`
	Version  string   `json:"version"`
	OS       string   `json:"os,omitempty"`
	Features []string `json:"features,omitempty"`
}

// AuthMsg carries credentials. The body is never logged.
type AuthMsg struct {
	Type     string `json:"type"`   // "auth"
	Method   string `json:"method"` // "none" | "password" | "token"
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Resume   string `json:"resume,omitempty"` // optional session id for reattach
}

// AuthResultMsg reports the outcome of authentication.
type AuthResultMsg struct {
	Type     string `json:"type"` // "auth_result"
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Session  string `json:"session,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// TerminalStartMsg is sent by the client to request a shell. The server never
// accepts an arbitrary command here: the command is fixed by server policy.
type TerminalStartMsg struct {
	Type string `json:"type"` // "terminal_start"
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Term string `json:"term,omitempty"` // TERM value requested by the client
	Cwd  string `json:"cwd,omitempty"`  // optional, validated by the server
	// ColorScheme hints whether the client renders on a dark background.
	ColorScheme string `json:"color_scheme,omitempty"`
}

// TerminalResizeMsg changes the PTY window size.
type TerminalResizeMsg struct {
	Type string `json:"type"` // "resize"
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// TerminalSignalMsg asks the server to deliver a signal to the shell process.
type TerminalSignalMsg struct {
	Type string `json:"type"` // "signal"
	Name string `json:"name"` // "INT" | "TERM" | "HUP" | "QUIT" | "KILL" | "WINCH" | "TSTP" | "CONT"
}

// TerminalExitMsg reports that the remote shell process finished.
type TerminalExitMsg struct {
	Type string `json:"type"` // "exit"
	Code int    `json:"code"`
	// Signal is the signal name when the process was terminated by a signal.
	Signal string `json:"signal,omitempty"`
}

// SessionInfoMsg describes the live session; used by the session manager UI.
type SessionInfoMsg struct {
	Type     string    `json:"type"` // "session_info"
	Session  string    `json:"session"`
	Shell    string    `json:"shell,omitempty"`
	Cols     int       `json:"cols"`
	Rows     int       `json:"rows"`
	Client   string    `json:"client,omitempty"`
	Started  time.Time `json:"started"`
	LastSeen time.Time `json:"last_seen"`
	PID      int       `json:"pid,omitempty"`
}

// DisconnectMsg is the polite goodbye sent before closing the socket.
type DisconnectMsg struct {
	Type    string `json:"type"` // "disconnect"
	Reason  string `json:"reason,omitempty"`
	Forced  bool   `json:"forced,omitempty"`
	Message string `json:"message,omitempty"`
}

// SessionsRequestMsg asks the host for its live session table.
type SessionsRequestMsg struct {
	Type string `json:"type"` // "sessions_request"
}

// SessionEntry is one row of the host's session table. It carries no
// credentials and no terminal content.
type SessionEntry struct {
	ID       string    `json:"id"`
	Client   string    `json:"client"`
	Shell    string    `json:"shell"`
	Cols     int       `json:"cols"`
	Rows     int       `json:"rows"`
	Auth     string    `json:"auth"`
	State    string    `json:"state"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	PID      int       `json:"pid,omitempty"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	// Self marks the session that made the query, so the client can label it.
	Self bool `json:"self,omitempty"`
}

// SessionsListMsg is the host's reply.
type SessionsListMsg struct {
	Type     string         `json:"type"` // "sessions_list"
	Sessions []SessionEntry `json:"sessions"`
	Max      int            `json:"max,omitempty"`
}

// ErrorMsg carries a human-readable failure.
type ErrorMsg struct {
	Type    string `json:"type"` // "error"
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PingMsg / PongMsg are application-level keepalives. The WebSocket layer also
// runs its own protocol-level ping/pong.
type PingMsg struct {
	Type string `json:"type"` // "ping"
	Seq  uint64 `json:"seq"`
	TS   int64  `json:"ts"` // unix millis
}

type PongMsg struct {
	Type string `json:"type"` // "pong"
	Seq  uint64 `json:"seq"`
	TS   int64  `json:"ts"`
}

// Error codes surfaced to the user.
const (
	ErrCodeProtocol     = "protocol_mismatch"
	ErrCodeAuth         = "auth_failed"
	ErrCodeSessionLimit = "session_limit"
	ErrCodePTY          = "pty_failed"
	ErrCodeShell        = "shell_failed"
	ErrCodeResize       = "resize_failed"
	ErrCodeInternal     = "internal_error"
	ErrCodeBadMessage   = "bad_message"
)

// NewError builds an ErrorMsg.
func NewError(code, msg string) *ErrorMsg {
	return &ErrorMsg{Type: "error", Code: code, Message: msg}
}
