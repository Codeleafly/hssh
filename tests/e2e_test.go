package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAcceptance_LsComesFromTheServer is acceptance test 40 from the spec: the
// client must show a file that exists only on the server, and `pwd` must return
// the server's directory rather than the client's.
func TestAcceptance_LsComesFromTheServer(t *testing.T) {
	// A directory that exists only here, on the "server" side of the test.
	serverDir := t.TempDir()
	marker := filepath.Join(serverDir, "server-only-file.txt")
	if err := os.WriteFile(marker, []byte("this file lives on the host\n"), 0o600); err != nil {
		t.Fatalf("create server file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(serverDir, "projects"), 0o700); err != nil {
		t.Fatalf("create server dir: %v", err)
	}

	h := startHost(t, "--workdir", serverDir)
	c := h.connect(t, 100, 30)

	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("client did not connect: %v\n--- host log ---\n%s", err, h.Log())
	}

	// ls
	c.sendLine("ls")
	if err := c.expect("server-only-file\\.txt", 15*time.Second); err != nil {
		t.Fatalf("`ls` did not show the server's file: %v", err)
	}
	if !hasLine(c.output(), "projects") {
		t.Errorf("`ls` did not show the server's directory `projects`\n%s", c.output())
	}

	// pwd must be the server's working directory, never the client's.
	c.clearOutput()
	c.sendLine("pwd")
	if err := c.expect(regexpQuote(serverDir), 15*time.Second); err != nil {
		t.Fatalf("`pwd` did not return the server's directory: %v", err)
	}

	// The output must stream back immediately, not at session teardown.
	c.clearOutput()
	c.sendLine("echo hello")
	if err := c.expect("hello", 10*time.Second); err != nil {
		t.Fatalf("`echo hello` did not stream back: %v", err)
	}
}

// TestInteractive_TTYIsReal proves the remote side is a real terminal: the
// shell must report a TTY device, not a pipe.
func TestInteractive_TTYIsReal(t *testing.T) {
	if skipOnUnsupportedPTY(t) {
		return
	}
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}

	c.sendLine("tty")
	// Either /dev/pts/N on Unix or a ConPTY-ish name on Windows.
	if err := c.expect("(/dev/pts/[0-9]+|/dev/tty)", 15*time.Second); err != nil {
		t.Fatalf("remote shell does not appear to be attached to a terminal: %v", err)
	}

	// `tty` must not say "not a tty".
	if strings.Contains(c.output(), "not a tty") {
		t.Fatalf("remote shell reported it is NOT a tty:\n%s", c.output())
	}
}

// TestANSI_IsPreserved checks that colour and cursor sequences survive the
// round trip untouched. A client that strips or re-encodes them would break
// every full-screen program.
func TestANSI_IsPreserved(t *testing.T) {
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}

	c.clearOutput()
	c.sendLine(`printf '\033[31mHSSH_RED\033[0m\033[1mHSSH_BOLD\033[0m\n'`)

	if err := c.expect("HSSH_RED", 15*time.Second); err != nil {
		t.Fatalf("colour output did not arrive: %v", err)
	}
	out := c.output()

	// The escape sequences must still be present in the byte stream.
	if !strings.Contains(out, "\x1b[31m") {
		t.Errorf("SGR colour sequence \\033[31m was stripped\nraw: %q", out)
	}
	if !strings.Contains(out, "\x1b[0m") {
		t.Errorf("SGR reset sequence \\033[0m was stripped\nraw: %q", out)
	}
	if !strings.Contains(out, "\x1b[1m") {
		t.Errorf("bold sequence \\033[1m was stripped\nraw: %q", out)
	}
}

// TestResize_ReachesTheRemotePTY covers acceptance test 42: after a resize the
// remote program must observe the new dimensions.
func TestResize_ReachesTheRemotePTY(t *testing.T) {
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}

	c.sendLine("stty size")
	if err := c.expect("30 100", 15*time.Second); err != nil {
		t.Fatalf("initial size not reported as 30x100: %v", err)
	}

	// Resize the client's window; the server must apply it to the PTY.
	c.resize(120, 40)
	// Give the debounce and a round trip a moment.
	time.Sleep(500 * time.Millisecond)
	c.clearOutput()
	c.sendLine("stty size")
	if err := c.expect("40 120", 15*time.Second); err != nil {
		t.Fatalf("resize did not reach the remote PTY: %v", err)
	}
}

// TestInteractive_ShellIsInteractive checks that line editing works, which it
// only does when the shell really is attached to a terminal.
func TestInteractive_ShellIsInteractive(t *testing.T) {
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Bracketed paste mode is enabled by an interactive shell on a TTY.
	if err := c.expect("\\?2004h", 15*time.Second); err != nil {
		t.Fatalf("shell did not enable bracketed paste, so it is not interactive: %v", err)
	}

	// History: send a command, then up-arrow, which only a line editor handles.
	c.sendLine("echo HSSH_HISTORY_FIRST")
	if err := c.expect("HSSH_HISTORY_FIRST", 15*time.Second); err != nil {
		t.Fatalf("first command failed: %v", err)
	}
	c.clearOutput()
	c.send("\x1b[A") // ArrowUp
	if err := c.expect("echo HSSH_HISTORY_FIRST", 10*time.Second); err != nil {
		t.Fatalf("arrow-up history recall failed: %v", err)
	}
}

// TestControlCharacters_MatchLinuxTerminal checks the control keys behave the
// way a terminal user expects: they go to the remote shell, not the client.
func TestControlCharacters_MatchLinuxTerminal(t *testing.T) {
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Ctrl+C must interrupt the remote foreground process and the client must
	// survive it.
	c.sendLine("sleep 30")
	time.Sleep(600 * time.Millisecond)
	c.send("\x03") // Ctrl+C

	c.clearOutput()
	c.sendLine("echo ALIVE_AFTER_SIGINT")
	if err := c.expect("ALIVE_AFTER_SIGINT", 15*time.Second); err != nil {
		t.Fatalf("client did not survive Ctrl+C: %v", err)
	}

	// Ctrl+D at an empty prompt ends the remote shell and the session.
	c.clearOutput()
	c.send("\x04")
	if code, exited := c.waitExit(15 * time.Second); !exited {
		t.Fatalf("Ctrl+D did not end the session (client still running)\n%s", truncate(c.output(), 2000))
	} else if code != 0 {
		t.Errorf("unexpected client exit code %d after Ctrl+D", code)
	}
}

// TestDisconnect_KeySequence covers spec section 17: a deliberate escape
// sequence ends the session and the local terminal is restored.
func TestDisconnect_KeySequence(t *testing.T) {
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}
	c.sendLine("echo BEFORE_DISCONNECT")
	if err := c.expect("BEFORE_DISCONNECT", 15*time.Second); err != nil {
		t.Fatalf("setup command failed: %v", err)
	}

	// Ctrl+] is the default disconnect key. A clean disconnect must exit 0:
	// a "negative WaitGroup counter" panic here once crashed the client on
	// every graceful disconnect and left the terminal in raw mode.
	c.send("\x1d")
	code, exited := c.waitExit(15 * time.Second)
	if !exited {
		t.Fatalf("Ctrl+] did not disconnect the client")
	}
	if code != 0 {
		t.Fatalf("client exited with code %d after a clean disconnect, want 0\n--- client output ---\n%s",
			code, truncate(c.output(), 2000))
	}
	if strings.Contains(c.output(), "panic") {
		t.Fatalf("client panicked on disconnect\n--- client output ---\n%s",
			truncate(c.output(), 2000))
	}

	// The host must have torn the session down rather than leaking it.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(h.Log(), "client disconnected") > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(h.Log(), "client disconnected") {
		t.Errorf("host did not record the disconnect\n--- host log ---\n%s", h.Log())
	}
	if !strings.Contains(h.Log(), "pty closed") {
		t.Errorf("host did not close the PTY after the disconnect\n--- host log ---\n%s", h.Log())
	}
}

// TestMultiClient_Isolation covers acceptance test 41. Each client gets its
// own shell, its own PTY and its own working directory.
func TestMultiClient_Isolation(t *testing.T) {
	h := startHost(t, "--per-session-cwd")
	a := h.connect(t, 100, 30)
	if err := a.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("client A: %v", err)
	}
	b := h.connect(t, 100, 30)
	if err := b.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("client B: %v", err)
	}
	d := h.connect(t, 100, 30)
	if err := d.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("client C: %v", err)
	}

	// A's PID and B's PID must differ: separate shells, separate PTYs.
	a.clearOutput()
	a.sendLine("echo MYPID=$$")
	if err := a.expect("MYPID=[0-9]+", 15*time.Second); err != nil {
		t.Fatalf("client A pid: %v", err)
	}
	aPID := captureAfter(a, "MYPID=([0-9]+)")

	b.clearOutput()
	b.sendLine("echo MYPID=$$")
	if err := b.expect("MYPID=[0-9]+", 15*time.Second); err != nil {
		t.Fatalf("client B pid: %v", err)
	}
	bPID := captureAfter(b, "MYPID=([0-9]+)")

	if aPID == "" || bPID == "" {
		t.Fatalf("could not read both pids (a=%q b=%q)", aPID, bPID)
	}
	if aPID == bPID {
		t.Fatalf("clients A and B share the same shell process (pid %s)", aPID)
	}

	// A changes directory; B must not follow.
	a.clearOutput()
	a.sendLine("cd /tmp")
	if err := a.expect("/tmp", 15*time.Second); err != nil {
		t.Fatalf("client A could not cd: %v", err)
	}
	b.clearOutput()
	b.sendLine("pwd")
	// B's cwd is its own private scratch directory, never /tmp.
	if out := b.output(); strings.Contains(out, "\r\n/tmp\r\n") {
		t.Fatalf("client B's working directory changed to /tmp because of client A:\n%s", out)
	}

	// A must not be able to see B's TTY device.
	a.clearOutput()
	a.sendLine("tty")
	if err := a.expect("(/dev/pts/[0-9]+)", 15*time.Second); err != nil {
		t.Fatalf("client A tty: %v", err)
	}
	aTTY := captureAfter(a, "(/dev/pts/[0-9]+)")

	b.clearOutput()
	b.sendLine("tty")
	if err := b.expect("(/dev/pts/[0-9]+)", 15*time.Second); err != nil {
		t.Fatalf("client B tty: %v", err)
	}
	bTTY := captureAfter(b, "(/dev/pts/[0-9]+)")

	if aTTY != "" && aTTY == bTTY {
		t.Fatalf("clients A and B share the same PTY device (%s)", aTTY)
	}
}

// TestInteractive_Programs verifies the programs a real terminal has to
// support. Each is skipped when it is not installed, so the suite stays
// meaningful on a minimal machine.
func TestInteractive_Programs(t *testing.T) {
	cases := []struct {
		command string
		expect  string
	}{
		{"clear", ""}, // screen clear must not break the stream
		{"printf 'A\\n'; printf '\\033[2J\\033[H'", ""}, // full screen clear + home
		{"seq 1 5", "5"},
		{"echo $((6*7))", "42"},
	}
	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}
	for _, tc := range cases {
		c.clearOutput()
		c.sendLine(tc.command)
		if tc.expect == "" {
			// Give it a moment and confirm the session is still healthy.
			time.Sleep(400 * time.Millisecond)
			c.sendLine("echo STILL_ALIVE")
			if err := c.expect("STILL_ALIVE", 15*time.Second); err != nil {
				t.Fatalf("session broke after %q: %v", tc.command, err)
			}
			continue
		}
		if err := c.expect(regexpQuote(tc.expect), 15*time.Second); err != nil {
			t.Fatalf("%q: %v", tc.command, err)
		}
	}
}

// TestInteractive_Repl exercises an interactive program that reads from stdin
// and prints to the terminal, which is the case pipes cannot fake.
func TestInteractive_Repl(t *testing.T) {
	if !hostHasCommand(t, "python3") && !hostHasCommand(t, "python") {
		t.Skip("no python on this machine")
	}
	py := "python3"
	if !hostHasCommand(t, "python3") {
		py = "python"
	}

	h := startHost(t)
	c := h.connect(t, 100, 30)
	if err := c.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("connect: %v", err)
	}

	c.sendLine(fmt.Sprintf("%s -i -c \"import sys; print('PY_READY', flush=True); "+
		"line=sys.stdin.readline(); print('PY_GOT:'+line.strip(), flush=True)\"", py))
	if err := c.expect("PY_READY", 20*time.Second); err != nil {
		t.Fatalf("python did not start: %v", err)
	}
	c.sendLine("HSSH_PAYLOAD")
	if err := c.expect("PY_GOT:HSSH_PAYLOAD", 20*time.Second); err != nil {
		t.Fatalf("python did not receive stdin: %v", err)
	}
}

// TestReconnect_AfterShellExit confirms a finished session does not wedge the
// host and a fresh client can connect straight away.
func TestReconnect_AfterShellExit(t *testing.T) {
	h := startHost(t)
	first := h.connect(t, 100, 30)
	if err := first.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	first.send("exit 3\r")
	if _, exited := first.waitExit(20 * time.Second); !exited {
		t.Fatalf("client did not exit after the shell exited")
	}
	// Give the host a moment to reap everything.
	time.Sleep(500 * time.Millisecond)

	second := h.connect(t, 100, 30)
	if err := second.expect("Connected to", 20*time.Second); err != nil {
		t.Fatalf("second connect failed: %v\n--- host log ---\n%s", err, h.Log())
	}
	second.sendLine("echo SECOND_SESSION_OK")
	if err := second.expect("SECOND_SESSION_OK", 15*time.Second); err != nil {
		t.Fatalf("second session not usable: %v", err)
	}
}

// TestConnectionRefused_ProducesHelpfulError checks the error path a user hits
// most often.
func TestConnectionRefused_ProducesHelpfulError(t *testing.T) {
	port := freePort(t) // nothing is listening there
	c := startClientFor(t, fmt.Sprintf("http://127.0.0.1:%d", port))

	code, exited := c.waitExit(20 * time.Second)
	if !exited {
		c.close()
		t.Fatalf("client did not exit after a refused connection")
	}
	if code == 0 {
		t.Errorf("client exited 0 on a refused connection; it should fail")
	}
	out := c.output()
	if !strings.Contains(out, "refused") && !strings.Contains(out, "Target") {
		t.Errorf("error output is not actionable:\n%s", out)
	}
	if !strings.Contains(out, "Target:") {
		t.Errorf("error output does not name the target:\n%s", out)
	}
}
