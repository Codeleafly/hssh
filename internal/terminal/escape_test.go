package terminal

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseEscapeKey(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"0x1d", []byte{0x1d}},
		{"1D", []byte{0x1d}},
		{"C-]", []byte{0x1d}},
		{"~.", []byte("~.")},
		{"C-[", []byte{0x1b}},
		{"C-\\", []byte{0x1c}},
		{"C-^", []byte{0x1e}},
		{"1b 5b", []byte{0x1b, '['}},
		{"0x1b,0x5b", []byte{0x1b, '['}},
	}
	for _, c := range cases {
		got, err := ParseEscapeKey(c.in)
		if err != nil {
			t.Fatalf("ParseEscapeKey(%q): %v", c.in, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatalf("ParseEscapeKey(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// Anything that is not a hex byte, a C- key or a literal string is a
	// configuration error the user needs told about.
	for _, bad := range []string{"", "0xzz", "0x1ff", "C-", "C-ab", "C-\u00e9"} {
		if _, err := ParseEscapeKey(bad); err == nil {
			t.Fatalf("ParseEscapeKey(%q) should fail", bad)
		}
	}
}

func TestEscapeParserForwardsOrdinaryInput(t *testing.T) {
	p := NewEscapeParser()
	in := []byte("ls -la\r\ngrep foo | wc -l\rmkdir -p a/b/c\r")
	out, disc := p.Filter(in)
	if disc {
		t.Fatal("no disconnect sequence was typed")
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("input was altered:\n got %q\nwant %q", out, in)
	}
}

func TestEscapeParserCatchesCtrlBracket(t *testing.T) {
	p := NewEscapeParser()
	out, disc := p.Filter([]byte("echo hi\r\x1d"))
	if !disc {
		t.Fatal("Ctrl+] should disconnect")
	}
	// The bytes before the escape are forwarded; nothing after it leaks.
	if !bytes.Equal(out, []byte("echo hi\r")) {
		t.Fatalf("forwarded bytes = %q", out)
	}
}

func TestEscapeParserTildeDotOnlyAtLineStart(t *testing.T) {
	// "~." is the OpenSSH escape and must only fire at the start of a line,
	// otherwise typing "foo ~. bar" would drop the session.
	p := NewEscapeParser([]byte("~."))
	out, disc := p.Filter([]byte("echo a~.b\r"))
	if disc {
		t.Fatalf("~. mid-line triggered a disconnect: forwarded %q", out)
	}
	if !strings.Contains(string(out), "~.") {
		t.Fatalf("~. was swallowed: %q", out)
	}

	p2 := NewEscapeParser([]byte("~."))
	out2, disc2 := p2.Filter([]byte("~.rest"))
	if !disc2 {
		t.Fatalf("~. at line start should disconnect, forwarded %q", out2)
	}
	if !bytes.Equal(out2, []byte("rest")) {
		t.Fatalf("bytes after the escape should pass through, got %q", out2)
	}
}

func TestEscapeParserHandlesSplitSequence(t *testing.T) {
	// A WebSocket frame boundary can fall in the middle of the escape. The
	// parser must hold the partial bytes rather than leaking them to the shell.
	p := NewEscapeParser([]byte{0x1b, 0x5b, 0x41})
	out, disc := p.Filter([]byte{0x1b, 0x5b})
	if disc {
		t.Fatal("an incomplete sequence must not disconnect")
	}
	if len(out) != 0 {
		t.Fatalf("partial sequence leaked to the shell: %q", out)
	}
	out, disc = p.Filter([]byte{0x41})
	if !disc {
		t.Fatal("the completed sequence should disconnect")
	}
}

func TestEscapeParserFlushesOnMismatch(t *testing.T) {
	// A byte that can never start a sequence must be delivered immediately, or
	// typing would feel laggy.
	p := NewEscapeParser([]byte{0x1d})
	out, disc := p.Filter([]byte("abc"))
	if disc {
		t.Fatal("unexpected disconnect")
	}
	if string(out) != "abc" {
		t.Fatalf("input not forwarded: %q", out)
	}
	// And the following real escape still works.
	_, disc = p.Filter([]byte{0x1d})
	if !disc {
		t.Fatal("escape after normal text was missed")
	}
}

func TestEscapeParserCarriesPartialOverMultipleReads(t *testing.T) {
	p := NewEscapeParser([]byte{'~', '.'})
	for i, b := range []byte{'~', '.'} {
		out, disc := p.Filter([]byte{b})
		if i < 1 && disc {
			t.Fatal("disconnected too early")
		}
		if i < 1 && len(out) != 0 {
			t.Fatalf("byte %d leaked early: %q", i, out)
		}
		if i == 1 && !disc {
			t.Fatal("did not disconnect on the final byte")
		}
	}
}

func TestEscapeParserBackspaceKeepsLineStart(t *testing.T) {
	// After backspacing over your own typing you are still logically at the
	// start of the line, so "~." should still work.
	p := NewEscapeParser([]byte("~."))
	_, _ = p.Filter([]byte("ab\x7f\x7f"))
	_, disc := p.Filter([]byte("~."))
	if !disc {
		t.Fatal("~. after backspacing should disconnect")
	}
}

func TestEscapeParserResetsLineStartOnNewline(t *testing.T) {
	p := NewEscapeParser([]byte("~."))
	_, disc := p.Filter([]byte("abc~."))
	if disc {
		t.Fatal("~. mid-line should not disconnect")
	}
	_, disc = p.Filter([]byte("\r~."))
	if !disc {
		t.Fatal("~. on a new line should disconnect")
	}
}

func TestEscapeParserHandlesCRLF(t *testing.T) {
	p := NewEscapeParser([]byte("~."))
	_, disc := p.Filter([]byte("x\r\n~."))
	if !disc {
		t.Fatal("~. after CRLF should disconnect")
	}
}

func TestEscapeParserEmptyInput(t *testing.T) {
	p := NewEscapeParser()
	out, disc := p.Filter(nil)
	if disc || len(out) != 0 {
		t.Fatalf("empty input should be a no-op, got %q %v", out, disc)
	}
}

func TestEscapeParserCustomSequence(t *testing.T) {
	p := NewEscapeParser([]byte("@@@"))
	out, disc := p.Filter([]byte("echo hello\r@@@"))
	if !disc {
		t.Fatal("custom sequence not detected")
	}
	if string(out) != "echo hello\r" {
		t.Fatalf("forwarded = %q", out)
	}
}

func TestEscapeParserDoesNotFireWithoutMatch(t *testing.T) {
	p := NewEscapeParser([]byte{0x02})
	for i := 0; i < 100; i++ {
		if _, disc := p.Filter([]byte{byte('a' + i%26)}); disc {
			t.Fatalf("unexpected disconnect on byte %d", i)
		}
	}
}

func TestSizeAndRawModeRejectNonTerminal(t *testing.T) {
	// A regular file is not a terminal; the client must fail loudly rather than
	// pretend to be interactive.
	f, err := openTempFile()
	if err != nil {
		t.Skipf("cannot create a temp file: %v", err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Skip("the temp file happens to be a terminal in this environment")
	}
	if _, err := MakeRaw(f); err == nil {
		t.Fatal("MakeRaw on a non-terminal should fail")
	}
	if _, err := SizeOf(f); err == nil {
		t.Fatal("SizeOf on a non-terminal should fail")
	}
}

func TestStateRestoreIsIdempotent(t *testing.T) {
	// Restoring twice must be safe, because the CLI restores from both the
	// normal path and the panic/signal path.
	var s *State
	if err := s.Restore(); err != nil {
		t.Fatalf("restoring a nil state should be a no-op, got %v", err)
	}
	if s.Active() {
		t.Fatal("a nil state must not report Active")
	}
}

// openTempFile creates a regular file for the non-terminal tests.
func openTempFile() (*os.File, error) {
	return os.CreateTemp("", "hssh-test-*")
}
