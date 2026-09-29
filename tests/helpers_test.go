package e2e

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// startClientFor launches `hssh connect <target>` in a PTY without a host, for
// testing the failure paths.
func startClientFor(t *testing.T, target string, extra ...string) *terminalClient {
	t.Helper()
	bin := binaryPath(t)
	args := append([]string{"connect", target}, extra...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HSSH_ASCII=1", "NO_COLOR=1", "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 100, Rows: 30})
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	c := &terminalClient{t: t, ptmx: ptmx, cmd: cmd, done: make(chan struct{})}
	t.Cleanup(c.close)
	go func() {
		defer close(c.done)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				c.mu.Lock()
				c.seen.Write(buf[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

// hostHasCommand reports whether a command exists on this machine, which is the
// same machine the host under test will use.
func hostHasCommand(t *testing.T, name string) bool {
	t.Helper()
	_, err := exec.LookPath(name)
	return err == nil
}

// skipOnUnsupportedPTY skips a test where the platform has no PTY.
func skipOnUnsupportedPTY(t *testing.T) bool {
	t.Helper()
	f, sfd, err := pty.Open()
	if err != nil {
		t.Skipf("no pty support here: %v", err)
	}
	_ = f.Close()
	_ = sfd.Close()
	return false
}

func regexpQuote(s string) string { return regexp.QuoteMeta(s) }

// extractGroup returns the first capture group of a pattern in s, or "".
func extractGroup(s, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// captureAfter runs a command and returns everything rendered after it, so a
// value can be extracted from the last occurrence rather than the first.
func captureAfter(c *terminalClient, pattern string) string {
	// The client accumulates output; the most recent match is the one we want.
	out := c.output()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	ms := re.FindAllStringSubmatch(out, -1)
	if len(ms) == 0 {
		return out
	}
	last := ms[len(ms)-1]
	if len(last) < 2 {
		return ""
	}
	return last[1]
}
