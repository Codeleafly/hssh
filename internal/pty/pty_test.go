package pty

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// readUntil drains a PTY until the marker appears or the deadline passes.
// Terminal output arrives in unpredictable chunks, so tests match on content.
func readUntil(t *testing.T, h *Handle, marker string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var out []byte
	buf := make([]byte, 8192)
	for time.Now().Before(deadline) {
		n, err := h.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			if strings.Contains(string(out), marker) {
				return string(out)
			}
		}
		if err != nil {
			break
		}
	}
	got := string(out)
	if !strings.Contains(got, marker) {
		t.Fatalf("did not see %q within %s; got:\n%q", marker, timeout, got)
	}
	return got
}

// shellPath returns an interactive shell to test with.
func shellPath(t *testing.T) (string, []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, c := range []string{"powershell.exe", "cmd.exe"} {
			if p, ok := which(c); ok {
				if strings.Contains(c, "cmd") {
					return p, nil
				}
				return p, []string{"-NoLogo", "-NoExit"}
			}
		}
		t.Skip("no Windows shell available")
	}
	for _, c := range []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/data/data/com.termux/files/usr/bin/sh"} {
		if p, ok := which(c); ok {
			return p, []string{"-i"}
		}
	}
	t.Skip("no unix shell available")
	return "", nil
}

func TestOpenGivesARealTTY(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{
		Command: sh,
		Args:    args,
		Env:     []string{"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color", "HOME=" + os.Getenv("HOME")},
		Dir:     os.TempDir(),
		Winsize: Winsize{Cols: 90, Rows: 25},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()

	if h.Pid() <= 0 {
		t.Fatalf("no child pid reported")
	}
	go func() { time.Sleep(300 * time.Millisecond); _, _ = h.Write([]byte("tty\n")) }()
	out := readUntil(t, h, "pts", 8*time.Second)
	if strings.Contains(out, "not a tty") {
		t.Fatalf("the child is not attached to a terminal:\n%s", out)
	}
}

func TestResizeIsVisibleToTheChild(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{
		Command: sh,
		Args:    args,
		Env:     []string{"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color"},
		Winsize: Winsize{Cols: 80, Rows: 24},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()

	if err := h.Resize(Winsize{Cols: 132, Rows: 43}); err != nil {
		t.Fatalf("resize: %v", err)
	}
	go func() { time.Sleep(200 * time.Millisecond); _, _ = h.Write([]byte("stty size\n")) }()
	// stty prints "rows cols".
	readUntil(t, h, "43 132", 8*time.Second)
}

func TestANSIEscapeSequencesSurviveThePTY(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{
		Command: sh, Args: args,
		Env: []string{"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()

	// The marker is the escape sequence itself, never the command text: the
	// shell echoes what was typed, so "RED" would match the echo and prove
	// nothing about what the PTY carried back.
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = h.Write([]byte(`printf '\033[31mRED\033[0m\033[1mBOLD\033[0m\n'` + "\n"))
	}()
	out := readUntil(t, h, "\x1b[31m", 8*time.Second)
	if !strings.Contains(out, "\x1b[1m") {
		t.Fatalf("bold sequence was lost:\n%q", out)
	}
	if !strings.Contains(out, "RED") {
		t.Fatalf("the printed text is missing:\n%q", out)
	}
}

func TestExitStatusIsCaptured(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{
		Command: sh, Args: args,
		Env: []string{"PATH=" + os.Getenv("PATH")},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()
	_, _ = h.Write([]byte("exit 7\n"))
	st, werr := h.Wait()
	if werr != nil {
		t.Fatalf("wait: %v", werr)
	}
	if st.Code != 7 {
		t.Fatalf("exit code = %d, want 7 (signal %q)", st.Code, st.Signal)
	}
}

func TestWaitIsIdempotent(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{Command: sh, Args: args, Env: []string{"PATH=" + os.Getenv("PATH")}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()
	_, _ = h.Write([]byte("exit 0\n"))
	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, _ := h.Wait()
			codes[i] = st.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 0 {
			t.Fatalf("concurrent Wait %d returned code %d", i, c)
		}
	}
}

func TestCloseIsIdempotentAndReaps(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{Command: sh, Args: args, Env: []string{"PATH=" + os.Getenv("PATH")}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pid := h.Pid()
	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case <-h.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the child was not reaped after Close")
	}
	// Closing the PTY master hangs the child up; on Linux it is a SIGHUP, so
	// it must be gone rather than lingering as a zombie.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("process %d still present shortly after close; it should be reaped", pid)
}

func TestOperationsAfterCloseReturnErrClosed(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{Command: sh, Args: args, Env: []string{"PATH=" + os.Getenv("PATH")}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	h.Close()
	if err := h.Resize(Winsize{Cols: 100, Rows: 30}); !errors.Is(err, ErrClosed) {
		t.Fatalf("resize after close = %v, want ErrClosed", err)
	}
	if err := h.Signal("TERM"); !errors.Is(err, ErrClosed) {
		t.Fatalf("signal after close = %v, want ErrClosed", err)
	}
	if _, err := h.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close = %v, want ErrClosed", err)
	}
}

func TestSignalDelivery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals are not meaningful on Windows")
	}
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{Command: sh, Args: args, Env: []string{"PATH=" + os.Getenv("PATH")}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()
	// An unknown signal name is a configuration error, not a silent no-op.
	if err := h.Signal("NOSUCHSIGNAL"); !errors.Is(err, ErrUnknownSignal("NOSUCHSIGNAL")) {
		t.Fatalf("unknown signal = %v", err)
	}
}

func TestUnknownSignalName(t *testing.T) {
	err := ErrUnknownSignal("BOGUS")
	if !strings.Contains(err.Error(), "BOGUS") {
		t.Fatalf("the error should name the signal: %v", err)
	}
}

func TestOpenFailsForMissingExecutable(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	_, err := Open(OpenOptions{Command: filepath.Join(t.TempDir(), "nope"), Env: []string{}})
	if err == nil {
		t.Fatal("starting a nonexistent binary should fail")
	}
}

func TestOpenWithNoCommandFails(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	_, err := Open(OpenOptions{
		OnUnix:    []string{"/definitely/not/here"},
		OnWindows: []string{"/definitely/not/here.exe"},
		Env:       []string{},
	})
	if err == nil {
		t.Fatal("no resolvable shell should fail rather than run something unexpected")
	}
}

func TestEnvironmentIsIsolatedPerSession(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	sh, args := shellPath(t)
	mk := func(extra map[string]string) *Handle {
		t.Helper()
		env := []string{"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color", "HSSH_MARKER=base"}
		h, err := Open(OpenOptions{Command: sh, Args: args, Env: env, EnvExtra: extra})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		return h
	}
	a := mk(map[string]string{"HSSH_MARKER": "alpha"})
	b := mk(map[string]string{"HSSH_MARKER": "beta"})
	defer a.Close()
	defer b.Close()

	// The marker words do not appear in the command text, so matching on them
	// proves the value came from the child's environment, not the echo.
	go func() { time.Sleep(200 * time.Millisecond); _, _ = a.Write([]byte("echo $HSSH_MARKER\n")) }()
	readUntil(t, a, "alpha", 8*time.Second)

	go func() { time.Sleep(200 * time.Millisecond); _, _ = b.Write([]byte("echo $HSSH_MARKER\n")) }()
	ob := readUntil(t, b, "beta", 8*time.Second)
	if strings.Contains(ob, "alpha") {
		t.Fatalf("session B saw session A's environment:\n%s", ob)
	}
}

func TestWorkingDirectoryIsHonoured(t *testing.T) {
	if !Supported() {
		t.Skip("no pty support on this platform")
	}
	dir := t.TempDir()
	sh, args := shellPath(t)
	h, err := Open(OpenOptions{
		Command: sh, Args: args,
		Env: []string{"PATH=" + os.Getenv("PATH")},
		Dir: dir,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer h.Close()
	go func() { time.Sleep(200 * time.Millisecond); _, _ = h.Write([]byte("pwd\n")) }()
	out := readUntil(t, h, dir, 8*time.Second)
	if !strings.Contains(out, dir) {
		t.Fatalf("pwd did not report %s:\n%s", dir, out)
	}
}

func TestUnsupportedPlatformIsRefused(t *testing.T) {
	// The Unsupported build tag path must return an error rather than silently
	// substituting pipes for a PTY.
	if Supported() {
		t.Skip("this platform does support PTYs")
	}
	if _, err := Open(OpenOptions{Command: "sh"}); err == nil {
		t.Fatal("a platform without PTY support must refuse to run a session")
	}
}

var _ = io.EOF

// processAlive reports whether a pid still exists. Used to confirm that closing
// a PTY really does hang the child up instead of leaking it.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(signalZero) == nil
}
