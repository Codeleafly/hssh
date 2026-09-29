// Package protocol defines the HSSH wire protocol (HSSH/1).
//
// The protocol is intentionally split in two channels of the same WebSocket
// connection:
//
//   - Control messages: JSON text frames, small and infrequent.
//   - Terminal payload:  binary frames with a single leading opcode byte, so
//     raw terminal bytes never get JSON/base64 encoded.
//
// Frame layout (every frame, text or binary):
//
//	[1 byte opcode][payload...]
//
// Text frames carry JSON objects of the shape {"type":"<name>",...} and the
// opcode is MessageHello etc. Binary frames carry opaque terminal data and the
// opcode is always one of PayloadInput / PayloadOutput.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Version is the canonical protocol identifier.
const Version = "HSSH/1"

// VersionNumber is the numeric form used for negotiation.
const VersionNumber = 1

// Name and VersionString identify this implementation to the peer.
const (
	Name          = "hssh"
	VersionString = "1.0.0"
)

// OpCode is the first byte of every HSSH frame.
type OpCode uint8

const (
	// Payload frames.
	PayloadInput  OpCode = 0x01 // client -> server, raw stdin bytes
	PayloadOutput OpCode = 0x02 // server -> client, raw PTY bytes

	// Control frames (JSON bodies).
	MessageHello          OpCode = 0x10
	MessageAuth           OpCode = 0x11
	MessageAuthResult     OpCode = 0x12
	MessageTerminalStart  OpCode = 0x13
	MessageTerminalInput  OpCode = 0x14
	MessageTerminalResize OpCode = 0x15
	MessageTerminalSignal OpCode = 0x16
	MessageTerminalExit   OpCode = 0x17
	MessageSessionInfo    OpCode = 0x18
	MessageDisconnect     OpCode = 0x19
	MessageError          OpCode = 0x1A

	// Keepalive.
	MessagePing OpCode = 0x20
	MessagePong OpCode = 0x21

	// Introspection, used by `hssh sessions`.
	MessageSessionsRequest OpCode = 0x30
	MessageSessionsList    OpCode = 0x31
)

var opNames = map[OpCode]string{
	PayloadInput:  "input",
	PayloadOutput: "output",

	MessageHello:          "hello",
	MessageAuth:           "auth",
	MessageAuthResult:     "auth_result",
	MessageTerminalStart:  "terminal_start",
	MessageTerminalInput:  "terminal_input",
	MessageTerminalResize: "resize",
	MessageTerminalSignal: "signal",
	MessageTerminalExit:   "exit",
	MessageSessionInfo:    "session_info",
	MessageDisconnect:     "disconnect",
	MessageError:          "error",
	MessagePing:           "ping",
	MessagePong:           "pong",

	MessageSessionsRequest: "sessions_request",
	MessageSessionsList:    "sessions_list",
}

var opByName = func() map[string]OpCode {
	m := make(map[string]OpCode, len(opNames))
	for k, v := range opNames {
		m[v] = k
	}
	return m
}()

// String returns the wire name of the opcode.
func (o OpCode) String() string {
	if n, ok := opNames[o]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%02x)", uint8(o))
}

// OpCodeByName resolves a wire name back to its opcode.
func OpCodeByName(name string) (OpCode, bool) {
	o, ok := opByName[name]
	return o, ok
}

// IsPayload reports whether the opcode carries raw terminal bytes.
func (o OpCode) IsPayload() bool {
	return o == PayloadInput || o == PayloadOutput
}

// Errors returned by the codec.
var (
	ErrShortFrame  = errors.New("hssh: frame too short")
	ErrUnknownOp   = errors.New("hssh: unknown message type")
	ErrBadJSON     = errors.New("hssh: malformed control message")
	ErrFrameTooBig = errors.New("hssh: frame exceeds size limit")
	ErrBadUTF8     = errors.New("hssh: control message is not valid UTF-8")
)

// MaxControlFrame is the hard limit for a single JSON control frame. It keeps a
// malicious peer from allocating unbounded memory with one frame.
const MaxControlFrame = 1 << 20 // 1 MiB

// EncodePayload wraps raw bytes in a payload frame.
func EncodePayload(op OpCode, data []byte) []byte {
	out := make([]byte, 1+len(data))
	out[0] = byte(op)
	copy(out[1:], data)
	return out
}

// EncodeControl marshals msg into a text frame. The message must have a valid
// "type" field.
func EncodeControl(msg any) ([]byte, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > MaxControlFrame {
		return nil, ErrFrameTooBig
	}
	out := make([]byte, 1+len(raw))
	out[0] = byte(opForMessage(msg))
	copy(out[1:], raw)
	return out, nil
}

// opForMessage inspects the marshalled JSON for its declared type so the
// opcode byte and the JSON body can never disagree.
func opForMessage(msg any) OpCode {
	raw, err := json.Marshal(msg)
	if err != nil {
		return MessageError
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return MessageError
	}
	if op, ok := OpCodeByName(probe.Type); ok {
		return op
	}
	return MessageError
}

// Frame is a decoded HSSH frame.
type Frame struct {
	Op   OpCode
	Data []byte // payload only (opcode byte stripped)
	Raw  []byte // the original slice including the opcode byte
}

// Decode splits a raw WebSocket message into an opcode and payload. The
// returned Data aliases the input; callers that retain it must copy.
func Decode(buf []byte) (Frame, error) {
	if len(buf) < 1 {
		return Frame{}, ErrShortFrame
	}
	op := OpCode(buf[0])
	return Frame{Op: op, Data: buf[1:], Raw: buf}, nil
}

// DecodeControl decodes a frame whose opcode is a control message and unmarshals
// the body into out.
func DecodeControl(f Frame, out any) error {
	if f.Op.IsPayload() {
		return fmt.Errorf("hssh: %s is a payload frame, not a control message", f.Op)
	}
	// The limit applies to the whole frame, opcode byte included, so the
	// encoder and the decoder agree on exactly which payloads are legal.
	if len(f.Raw) > MaxControlFrame {
		return ErrFrameTooBig
	}
	if !utf8.Valid(f.Data) {
		return ErrBadUTF8
	}
	if err := json.Unmarshal(f.Data, out); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	return nil
}

// EncodeUint16 / DecodeUint16 are helpers for little helpers elsewhere.
func EncodeUint16(v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return b[:]
}

// DecodeUint16 reads a little-endian uint16.
func DecodeUint16(b []byte) (uint16, error) {
	if len(b) < 2 {
		return 0, ErrShortFrame
	}
	return binary.LittleEndian.Uint16(b), nil
}
