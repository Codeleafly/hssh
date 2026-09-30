package terminal

import (
	"bytes"
	"net/url"
	"strings"
)

// This file implements live working-directory tracking the way VS Code does:
// shells with shell-integration enabled announce every directory change with
// an OSC 7 escape sequence:
//
//	ESC ] 7 ; file://hostname/path ST
//
// where ST is BEL (\x07) or ESC \. node-pty itself never tracks cwd —
// conhost/VS Code do it by watching the output stream — so HSSH does the
// same: the PTY pump observes output bytes and reports new directories.
// Output is never modified, only observed. Shells without integration simply
// never announce, and the creation-time directory stays on record.

// osc7Prefix starts a cwd announcement.
var osc7Prefix = []byte("\x1b]7;")

// osc7TermST is the ST (string terminator) form.
var osc7TermST = []byte("\x1b\\")

// maxOSC7Len bounds one announcement. Anything longer is not a cwd report.
const maxOSC7Len = 4096

// osc7Scanner watches PTY output for OSC 7 cwd reports.
type osc7Scanner struct {
	carry []byte
	last  string
}

// observe feeds output bytes. It returns the newly announced absolute
// directory when the shell reports one that differs from the previous
// announcement.
func (o *osc7Scanner) observe(p []byte) (string, bool) {
	if len(p) == 0 {
		return "", false
	}
	o.carry = append(o.carry, p...)
	if len(o.carry) > 2*maxOSC7Len {
		// A split sequence can only be completed by bytes near the end;
		// anything older is plain output.
		tail := append([]byte(nil), o.carry[len(o.carry)-maxOSC7Len:]...)
		o.carry = tail
	}
	dir, ok := lastOSC7Dir(o.carry)
	if !ok || dir == "" || dir == o.last {
		return "", false
	}
	o.last = dir
	return dir, true
}

// lastOSC7Dir returns the most recent valid directory announced in buf.
func lastOSC7Dir(buf []byte) (string, bool) {
	var found string
	var ok bool
	rest := buf
	for {
		i := bytes.Index(rest, osc7Prefix)
		if i < 0 {
			return found, ok
		}
		body := rest[i+len(osc7Prefix):]
		end, skip := osc7End(body)
		if end < 0 {
			// No terminator yet: a split sequence waiting for more bytes.
			return found, ok
		}
		if d, valid := parseOSC7URI(body[:end]); valid {
			found, ok = d, true
		}
		rest = body[skip:]
	}
}

// osc7End finds the terminator (BEL or ST) of an OSC body. It returns the
// body length and how many bytes to skip past the terminator, or -1 when the
// sequence is still incomplete.
func osc7End(body []byte) (end, skip int) {
	bel := bytes.IndexByte(body, '\x07')
	st := bytes.Index(body, osc7TermST)
	switch {
	case bel >= 0 && (st < 0 || bel < st):
		return bel, bel + 1
	case st >= 0:
		return st, st + 2
	default:
		return -1, -1
	}
}

// parseOSC7URI extracts the path from an OSC 7 body of the form
// "file://hostname/path". Only absolute paths are accepted; anything else
// (relative paths, other schemes, garbage) is ignored.
func parseOSC7URI(body []byte) (string, bool) {
	s := string(body)
	if !strings.HasPrefix(s, "file://") {
		return "", false
	}
	rest := s[len("file://"):]
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", false
	}
	path := rest[i:]
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	if dec, err := url.PathUnescape(path); err == nil {
		path = dec
	}
	if path == "" || len(path) > maxOSC7Len {
		return "", false
	}
	return path, true
}
