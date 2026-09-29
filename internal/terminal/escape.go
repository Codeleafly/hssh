package terminal

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Default disconnect sequences, recognised in the client's raw input stream
// and never forwarded to the remote shell.
//
//	0x1D          Ctrl+]  — the classic telnet escape, safe to use
//	"~."           OpenSSH's escape, typed at the start of a line
//
// Both can be replaced with --disconnect-key.
var (
	DefaultDisconnectKeys = [][]byte{{0x1D}, []byte("~.")}
)

// EscapeParser scans a raw byte stream for disconnect sequences and passes
// everything else through untouched.
//
// It is a longest-prefix matcher with a small carry buffer, so a sequence that
// straddles two reads (Ctrl+] arriving split across packets) is still caught
// without delaying ordinary keystrokes: as soon as the accumulated bytes fail
// to match any sequence, they are flushed to the output immediately.
type EscapeParser struct {
	seqs [][]byte
	// carry holds bytes that might still become a match.
	carry []byte
	// col is the cursor column on the current input line. It drives the
	// OpenSSH "~." convention, which only fires at the start of a line, and it
	// accounts for backspace so backspacing over your own typing counts as
	// being back at an empty line.
	col int
}

// lineStart reports whether the cursor sits at column zero of the input line.
func (p *EscapeParser) lineStart() bool { return p.col == 0 }

// ErrBadEscape is returned by ParseEscapeKey for a malformed --disconnect-key.
var ErrBadEscape = errors.New("invalid escape sequence")

// controlKeys maps the non-alphanumeric characters that conventionally stand
// for a control code, so "C-]" (the telnet escape) and "C-[" (Escape) can be
// written the way people actually say them.
var controlKeys = map[byte]byte{
	'@':  0x00, // Ctrl+@ (NUL)
	'[':  0x1b, // Ctrl+[ (Escape)
	'\\': 0x1c, // Ctrl+\\ (FS)
	']':  0x1d, // Ctrl+] (Group Separator, the classic telnet escape)
	'^':  0x1e, // Ctrl+^ (Record Separator)
	'_':  0x1f, // Ctrl+_ (Unit Separator)
	'?':  0x7f, // Ctrl+? (Delete)
	'/':  0x1f,
	' ':  0x00,
}

// controlChar converts a "C-x" style key name to its byte.
func controlChar(name, original string) ([]byte, error) {
	if len(name) != 1 {
		return nil, fmt.Errorf("%w: %s", ErrBadEscape, original)
	}
	c := name[0]
	if c >= 'a' && c <= 'z' {
		return []byte{c - 'a' + 1}, nil
	}
	if v, ok := controlKeys[c]; ok {
		return []byte{v}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrBadEscape, original)
}

// NewEscapeParser builds a parser for the given sequences.
func NewEscapeParser(seqs ...[]byte) *EscapeParser {
	if len(seqs) == 0 {
		seqs = DefaultDisconnectKeys
	}
	p := &EscapeParser{seqs: make([][]byte, 0, len(seqs))}
	for _, s := range seqs {
		if len(s) > 0 {
			p.seqs = append(p.seqs, append([]byte(nil), s...))
		}
	}
	return p
}

// ParseEscapeKey accepts "0x1d", "1D", "C-]", "~." or "3f 2e" and returns the
// raw bytes.
func ParseEscapeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrBadEscape
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "0x") {
		// "0x1d" is one byte, but "0x1b,0x5b" is a list, so only take the
		// single-byte path when the whole remainder really is one hex value.
		if v, err := strconv.ParseUint(lower[2:], 16, 8); err == nil {
			return []byte{byte(v)}, nil
		}
		// A value that was clearly meant as hex but is malformed is an error,
		// not a literal string.
		if !strings.ContainsAny(lower[2:], " ,:") {
			return nil, fmt.Errorf("%w: %s", ErrBadEscape, s)
		}
	}
	if strings.HasPrefix(lower, "c-") {
		return controlChar(lower[2:], s)
	}
	// A bare two-digit hex value is a single byte: "1d" is Ctrl+].
	if len(s) == 2 {
		if v, err := strconv.ParseUint(lower, 16, 8); err == nil {
			return []byte{byte(v)}, nil
		}
	}
	// Space or comma separated hex bytes, or a literal string.
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == ':' || r == '-'
	})
	if len(fields) > 1 {
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(f), "0x"), 16, 8)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrBadEscape, s)
			}
			out = append(out, byte(v))
		}
		return out, nil
	}
	return []byte(s), nil
}

// Filter consumes a chunk of raw input. It returns the bytes to forward to the
// server and reports whether a disconnect sequence completed.
func (p *EscapeParser) Filter(data []byte) (forward []byte, disconnect bool) {
	if p == nil {
		return data, false
	}
	if len(data) == 0 {
		return nil, false
	}
	buf := make([]byte, 0, len(data)+len(p.carry))
	buf = append(buf, p.carry...)
	buf = append(buf, data...)
	p.carry = p.carry[:0]

	out := make([]byte, 0, len(buf))

	i := 0
	for i < len(buf) {
		matched, consumed := p.matchAt(buf[i:], out)
		switch {
		case matched:
			disconnect = true
			i += consumed
			// Everything after the escape belongs to the next command.
			out = append(out, buf[i:]...)
			i = len(buf)
		case consumed > 0:
			// Partial match: hold the bytes, wait for more input.
			p.carry = append(p.carry, buf[i:i+consumed]...)
			i += consumed
		default:
			b := buf[i]
			out = append(out, b)
			switch {
			case b == '\n' || b == '\r':
				p.col = 0
			case b == 0x7f || b == 0x08:
				if p.col > 0 {
					p.col--
				}
			default:
				p.col++
			}
			i++
		}
	}
	return out, disconnect
}

// matchAt reports whether a sequence starts at the head of b. It returns
// (complete, n) where n>0 means n bytes are a prefix of some sequence.
func (p *EscapeParser) matchAt(b []byte, _ []byte) (complete bool, n int) {
	bestPartial := 0
	for _, seq := range p.seqs {
		// A multi-byte sequence such as "~." only counts at the start of a
		// line, matching OpenSSH.
		if len(seq) > 1 && !p.lineStart() {
			continue
		}
		common := 0
		for common < len(seq) && common < len(b) && seq[common] == b[common] {
			common++
		}
		if common == len(seq) {
			return true, common
		}
		if common > bestPartial {
			bestPartial = common
		}
	}
	return false, bestPartial
}
