package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPayloadRoundTripPreservesBytes(t *testing.T) {
	// Terminal data can be any byte sequence, including NULs, invalid UTF-8
	// and full escape sequences. The codec must not touch a single byte.
	payloads := [][]byte{
		[]byte("ls -la\r\n"),
		{0x00, 0x01, 0x02, 0xff, 0xfe},
		[]byte("\x1b[31mred\x1b[0m"),
		[]byte("\x1b]0;title\x07"),
		[]byte("日本語のテキスト"),
		bytes.Repeat([]byte("A"), 64*1024),
	}
	for _, p := range payloads {
		frame := EncodePayload(PayloadOutput, p)
		if len(frame) != len(p)+1 {
			t.Fatalf("payload length changed: got %d want %d", len(frame), len(p)+1)
		}
		if frame[0] != byte(PayloadOutput) {
			t.Fatalf("opcode not first byte: got 0x%02x", frame[0])
		}
		f, err := Decode(frame)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if f.Op != PayloadOutput {
			t.Fatalf("opcode mismatch: %v", f.Op)
		}
		if !bytes.Equal(f.Data, p) {
			t.Fatalf("payload corrupted:\n got %q\nwant %q", f.Data, p)
		}
	}
}

func TestDecodeRejectsEmptyFrame(t *testing.T) {
	if _, err := Decode(nil); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("want ErrShortFrame, got %v", err)
	}
	if _, err := Decode([]byte{}); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("want ErrShortFrame, got %v", err)
	}
}

func TestControlMessageOpCodeMatchesBody(t *testing.T) {
	msgs := []any{
		&HelloMsg{Type: "hello", Protocol: Version, Client: Name, Version: VersionString},
		&AuthMsg{Type: "auth", Method: "password", Password: "s3cret"},
		&AuthResultMsg{Type: "auth_result", OK: true},
		&TerminalStartMsg{Type: "terminal_start", Cols: 120, Rows: 40},
		&TerminalResizeMsg{Type: "resize", Cols: 80, Rows: 24},
		&TerminalSignalMsg{Type: "signal", Name: "INT"},
		&TerminalExitMsg{Type: "exit", Code: 0},
		&SessionInfoMsg{Type: "session_info", Session: "abc"},
		&DisconnectMsg{Type: "disconnect", Reason: "bye"},
		NewError(ErrCodeInternal, "boom"),
		&PingMsg{Type: "ping", Seq: 1},
		&PongMsg{Type: "pong", Seq: 1},
		&SessionsRequestMsg{Type: "sessions_request"},
		&SessionsListMsg{Type: "sessions_list"},
	}
	for _, m := range msgs {
		raw, err := EncodeControl(m)
		if err != nil {
			t.Fatalf("encode %T: %v", m, err)
		}
		f, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode %T: %v", m, err)
		}
		// The opcode byte and the JSON "type" must agree; a mismatch would let
		// a message be routed to the wrong handler.
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(f.Data, &probe); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		want, ok := OpCodeByName(probe.Type)
		if !ok {
			t.Fatalf("type %q has no opcode", probe.Type)
		}
		if f.Op != want {
			t.Fatalf("%T: opcode 0x%02x does not match type %q (0x%02x)",
				m, byte(f.Op), probe.Type, byte(want))
		}
	}
}

func TestDecodeControlRejectsPayloadFrame(t *testing.T) {
	raw := EncodePayload(PayloadInput, []byte("x"))
	f, _ := Decode(raw)
	var out HelloMsg
	if err := DecodeControl(f, &out); err == nil {
		t.Fatal("expected an error decoding a payload frame as control")
	}
}

func TestDecodeControlRejectsInvalidUTF8(t *testing.T) {
	// A JSON text frame must be UTF-8. Invalid bytes are a protocol violation,
	// not something to pass through to a JSON parser.
	raw := append([]byte{byte(MessageHello)}, 0xff, 0xfe, 0xfd)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out HelloMsg
	if err := DecodeControl(f, &out); !errors.Is(err, ErrBadUTF8) {
		t.Fatalf("want ErrBadUTF8, got %v", err)
	}
}

func TestDecodeControlRejectsMalformedJSON(t *testing.T) {
	raw := append([]byte{byte(MessageHello)}, []byte(`{"type":`)...)
	f, _ := Decode(raw)
	var out HelloMsg
	if err := DecodeControl(f, &out); !errors.Is(err, ErrBadJSON) {
		t.Fatalf("want ErrBadJSON, got %v", err)
	}
}

func TestDecodeControlRejectsOversizedFrame(t *testing.T) {
	big := append([]byte{byte(MessageHello)}, bytes.Repeat([]byte("a"), MaxControlFrame)...)
	f, _ := Decode(big)
	var out HelloMsg
	if err := DecodeControl(f, &out); !errors.Is(err, ErrFrameTooBig) {
		t.Fatalf("want ErrFrameTooBig, got %v", err)
	}
}

func TestEncodeControlRejectsOversizedMessage(t *testing.T) {
	// A control message larger than the limit must fail to encode rather than
	// be sent and rejected later.
	_, err := EncodeControl(&AuthMsg{Type: "auth", Method: "password", Password: strings.Repeat("x", MaxControlFrame)})
	if !errors.Is(err, ErrFrameTooBig) {
		t.Fatalf("want ErrFrameTooBig, got %v", err)
	}
}

func TestOpCodeNamesRoundTrip(t *testing.T) {
	for op, name := range opNames {
		got, ok := OpCodeByName(name)
		if !ok {
			t.Fatalf("name %q not resolvable", name)
		}
		if got != op {
			t.Fatalf("name %q maps to 0x%02x, want 0x%02x", name, byte(got), byte(op))
		}
		if op.String() != name {
			t.Fatalf("opcode 0x%02x string is %q, want %q", byte(op), op.String(), name)
		}
	}
}

func TestIsPayloadOnlyForDataFrames(t *testing.T) {
	if !PayloadInput.IsPayload() || !PayloadOutput.IsPayload() {
		t.Fatal("payload opcodes must report IsPayload")
	}
	for name, op := range opByName {
		if name == "input" || name == "output" {
			continue
		}
		if op.IsPayload() {
			t.Fatalf("control message %q must not report IsPayload", name)
		}
	}
}

func TestUnknownOpcodeHasSafeName(t *testing.T) {
	// An unknown opcode from a newer peer must not panic or leak raw bytes
	// into a log line unescaped.
	op := OpCode(0xEE)
	if got := op.String(); !strings.Contains(got, "0xee") {
		t.Fatalf("unknown opcode name is not informative: %q", got)
	}
	if _, ok := OpCodeByName(op.String()); ok {
		t.Fatal("an unknown opcode must not resolve back from its name")
	}
}

func TestErrorMsgCarriesCode(t *testing.T) {
	e := NewError(ErrCodeAuth, "bad password")
	if e.Type != "error" || e.Code != ErrCodeAuth || e.Message != "bad password" {
		t.Fatalf("unexpected error message: %+v", e)
	}
}

func TestUint16Helpers(t *testing.T) {
	b := EncodeUint16(0xBEEF)
	v, err := DecodeUint16(b)
	if err != nil || v != 0xBEEF {
		t.Fatalf("uint16 round trip failed: %v %v", v, err)
	}
	if _, err := DecodeUint16([]byte{1}); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("want ErrShortFrame for a short buffer, got %v", err)
	}
}

func TestVersionConstants(t *testing.T) {
	if Version != "HSSH/1" {
		t.Fatalf("protocol version must stay HSSH/1 for compatibility, got %q", Version)
	}
	if VersionNumber != 1 {
		t.Fatalf("version number mismatch: %d", VersionNumber)
	}
}
