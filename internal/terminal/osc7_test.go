package terminal

import (
	"strings"
	"testing"
)

func TestOSC7ReportsAbsoluteDir(t *testing.T) {
	var s osc7Scanner
	dir, ok := s.observe([]byte("prompt\x1b]7;file://host/tmp\x07$ "))
	if !ok || dir != "/tmp" {
		t.Fatalf("observe = %q, %v; want /tmp, true", dir, ok)
	}
	// The same announcement twice is not a change.
	if _, ok := s.observe([]byte("\x1b]7;file://host/tmp\x07")); ok {
		t.Fatal("a repeated announcement must not report a change")
	}
	// Plain output never reports.
	if _, ok := s.observe([]byte("ls -la\r\n/home/user\r\n")); ok {
		t.Fatal("plain output must not report a directory")
	}
}

func TestOSC7AcceptsSTTerminator(t *testing.T) {
	var s osc7Scanner
	dir, ok := s.observe([]byte("\x1b]7;file://host/var/log\x1b\\"))
	if !ok || dir != "/var/log" {
		t.Fatalf("observe = %q, %v; want /var/log, true", dir, ok)
	}
}

func TestOSC7HandlesSplitSequence(t *testing.T) {
	var s osc7Scanner
	if _, ok := s.observe([]byte("out\x1b]7;file://ho")); ok {
		t.Fatal("an incomplete sequence must not report")
	}
	dir, ok := s.observe([]byte("st/opt\x07more"))
	if !ok || dir != "/opt" {
		t.Fatalf("observe = %q, %v; want /opt, true", dir, ok)
	}
}

func TestOSC7TakesTheLastAnnouncement(t *testing.T) {
	var s osc7Scanner
	dir, ok := s.observe([]byte("\x1b]7;file://h/a\x07\x1b]7;file://h/b\x07"))
	if !ok || dir != "/b" {
		t.Fatalf("observe = %q, %v; want /b, true", dir, ok)
	}
}

func TestOSC7RejectsGarbage(t *testing.T) {
	var s osc7Scanner
	for _, bad := range []string{
		"\x1b]7;relative/path\x07", // not absolute
		"\x1b]7;https://h/x\x07",   // wrong scheme
		"\x1b]7;file://host\x07",   // no path at all
		"\x1b]0;window title\x07",  // OSC 0, not OSC 7
		"\x1b]7;file://host",       // unterminated
	} {
		if d, ok := s.observe([]byte(bad)); ok {
			t.Fatalf("garbage %q reported %q", bad, d)
		}
	}
}

func TestOSC7DecodesEscapes(t *testing.T) {
	var s osc7Scanner
	dir, ok := s.observe([]byte("\x1b]7;file://host/my%20docs\x07"))
	if !ok || dir != "/my docs" {
		t.Fatalf("observe = %q, %v; want /my docs, true", dir, ok)
	}
}

func TestOSC7IgnoresOverlongBodies(t *testing.T) {
	var s osc7Scanner
	huge := "\x1b]7;file://host/" + strings.Repeat("a", maxOSC7Len+1) + "\x07"
	if d, ok := s.observe([]byte(huge)); ok {
		t.Fatalf("overlong body reported %q", d)
	}
	// The scanner must still work afterwards.
	dir, ok := s.observe([]byte("\x1b]7;file://host/ok\x07"))
	if !ok || dir != "/ok" {
		t.Fatalf("observe = %q, %v; want /ok, true", dir, ok)
	}
}
