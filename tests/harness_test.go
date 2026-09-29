// Package e2e drives the real hssh binaries the way a person does: a host
// process, and a client process running inside a genuine PTY whose output is
// read back and matched.
//
// These tests deliberately avoid the client/server packages' own code paths for
// terminal handling. The client is launched as a subprocess attached to a PTY,
// typed into as a human would type, and its rendered output is inspected. That
// is the only way to prove the client is not simulating a terminal.
package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

// binaryPath returns the path to the hssh binary built for this test run.
func binaryPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HSSH_TEST_BINARY"); p != "" {
		return p
	}
	// tests/ lives one level below the module root.
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	p := filepath.Join(root, "bin", "hssh")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("hssh binary not built at %s (run: go build -o bin/hssh ./cmd/hssh)", p)
	}
	return p
}

// freePort reserves an ephemeral port and releases it, so the port is very
// likely free for the host under test.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// host is a running hssh host subprocess.
type host struct {
	t    *testing.T
	cmd  *exec.Cmd
	addr string
	log  *bytes.Buffer
	logM sync.Mutex
	// cleanup removes any PTYs/scratch dirs the host created.
	cleanup []func()
}

// startHost launches `hssh host` and waits until /health answers.
func startHost(t *testing.T, extraArgs ...string) *host {
	t.Helper()
	bin := binaryPath(t)
	port := freePort(t)

	args := append([]string{"host", "--port", fmt.Sprint(port), "--allow-unauthenticated",
		"--log-level", "debug"}, extraArgs...)

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HSSH_ASCII=1", "NO_COLOR=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("host stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("host stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start host: %v", err)
	}

	h := &host{
		t:    t,
		cmd:  cmd,
		addr: fmt.Sprintf("127.0.0.1:%d", port),
		log:  &bytes.Buffer{},
	}
	t.Cleanup(h.stop)

	// Drain both streams into a buffer the test can inspect on failure.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&lockedWriter{h: h}, stdout) }()
	go func() { defer wg.Done(); io.Copy(&lockedWriter{h: h}, stderr) }()
	go func() { wg.Wait(); h.logM.Lock(); h.logM.Unlock() }()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if h.healthy() {
			return h
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("host did not become healthy\n--- host log ---\n%s", h.Log())
	return nil
}

func (h *host) healthy() bool {
	resp, err := http.Get("http://" + h.addr + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Log returns the captured host output.
func (h *host) Log() string {
	h.logM.Lock()
	defer h.logM.Unlock()
	return h.log.String()
}

func (h *host) stop() {
	if h.cmd.Process == nil {
		return
	}
	_ = h.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _, _ = h.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = h.cmd.Process.Kill()
	}
	for _, c := range h.cleanup {
		c()
	}
}

type lockedWriter struct{ h *host }

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.h.logM.Lock()
	defer l.h.logM.Unlock()
	return l.h.log.Write(p)
}

// terminalClient is the hssh client running inside a real PTY, exactly as a
// user experiences it.
type terminalClient struct {
	t    *testing.T
	ptmx *os.File
	cmd  *exec.Cmd

	mu   sync.Mutex
	seen bytes.Buffer

	closed bool
	done   chan struct{}
}

// connect starts `hssh connect` inside a PTY of the given size.
func (h *host) connect(t *testing.T, cols, rows uint16, args ...string) *terminalClient {
	t.Helper()
	bin := binaryPath(t)

	full := append([]string{"connect", "http://" + h.addr}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), "HSSH_ASCII=1", "NO_COLOR=1", "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		t.Fatalf("start client in a pty: %v", err)
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

// send types raw bytes into the client's terminal, the way a keyboard would.
func (c *terminalClient) send(s string) {
	c.t.Helper()
	if _, err := c.ptmx.Write([]byte(s)); err != nil {
		c.t.Logf("write to client pty: %v", err)
	}
}

// sendLine types a line and presses Enter.
func (c *terminalClient) sendLine(s string) { c.send(s + "\r") }

// resize changes the client's window size, which must reach the remote PTY.
func (c *terminalClient) resize(cols, rows uint16) {
	c.t.Helper()
	if err := pty.Setsize(c.ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		c.t.Fatalf("resize client pty: %v", err)
	}
}

// output returns everything the client has rendered so far.
func (c *terminalClient) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen.String()
}

// expect waits for a pattern to appear in the client's rendered output.
func (c *terminalClient) expect(pat string, timeout time.Duration) error {
	re, err := regexp.Compile(pat)
	if err != nil {
		return fmt.Errorf("bad pattern %q: %w", pat, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if re.MatchString(c.output()) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for %q\n--- client output ---\n%s",
		timeout, pat, truncate(c.output(), 4000))
}

// expectAll waits for several patterns in any order.
func (c *terminalClient) expectAll(timeout time.Duration, pats ...string) error {
	deadline := time.Now().Add(timeout)
	for _, p := range pats {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			remaining = time.Millisecond
		}
		if err := c.expect(p, remaining); err != nil {
			return err
		}
	}
	return nil
}

// clearOutput discards what has been rendered so far.
func (c *terminalClient) clearOutput() {
	c.mu.Lock()
	c.seen.Reset()
	c.mu.Unlock()
}

// waitExit waits for the client process to end and returns its exit code.
func (c *terminalClient) waitExit(timeout time.Duration) (int, bool) {
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		return 0, true
	case <-time.After(timeout):
		return -1, false
	}
}

func (c *terminalClient) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(os.Kill)
	}
	_ = c.ptmx.Close()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... (truncated)"
}

// scanLines splits rendered output into lines, dropping empty ones. Terminal
// output arrives in unpredictable chunks, so assertions work on the line set.
func scanLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r\x1b")
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// hasLine reports whether any rendered line contains sub.
func hasLine(s, sub string) bool {
	for _, l := range scanLines(s) {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
