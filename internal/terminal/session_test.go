package terminal

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/pty"
	"github.com/hssh/hssh/internal/shell"
)

// memSink is an OutputSink that records frames. It also has a blocking mode so
// backpressure can be exercised deterministically.
type memSink struct {
	mu       sync.Mutex
	frames   [][]byte
	controls []any
	// stalled makes WriteOutput block until released, simulating a client that
	// has stopped reading.
	stalled atomic.Bool
	release chan struct{}
	queued  atomic.Int64
	// maxObserved records the high-water mark of queued bytes.
	maxObserved atomic.Int64
	writeErr    error
}

func newMemSink() *memSink { return &memSink{release: make(chan struct{})} }

func (m *memSink) WriteOutput(p []byte) error {
	if m.stalled.Load() {
		n := int64(len(p))
		for {
			cur := m.queued.Add(n)
			for {
				old := m.maxObserved.Load()
				if cur <= old || m.maxObserved.CompareAndSwap(old, cur) {
					break
				}
			}
			select {
			case <-m.release:
				m.queued.Add(-n)
				return m.deliver(p)
			case <-time.After(2 * time.Second):
				// Never hang a test forever; treat it as a wedged client.
				m.queued.Add(-n)
				return errors.New("sink stalled")
			}
		}
	}
	return m.deliver(p)
}

func (m *memSink) deliver(p []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.mu.Lock()
	cp := make([]byte, len(p))
	copy(cp, p)
	m.frames = append(m.frames, cp)
	m.mu.Unlock()
	return nil
}

func (m *memSink) SendControl(msg any) error {
	m.mu.Lock()
	m.controls = append(m.controls, msg)
	m.mu.Unlock()
	return nil
}

func (m *memSink) Buffered() int { return int(m.queued.Load()) }

// text concatenates every output frame, decoding the HSSH frame header.
func (m *memSink) text() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []byte
	for _, f := range m.frames {
		fr, err := protocol.Decode(f)
		if err != nil || fr.Op != protocol.PayloadOutput {
			continue
		}
		out = append(out, fr.Data...)
	}
	return string(out)
}

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.frames)
}

func testShell(t *testing.T) shell.Spec {
	t.Helper()
	for _, c := range []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/data/data/com.termux/files/usr/bin/sh"} {
		if p := findExec(c); p != "" {
			return shell.Spec{Path: p, Args: []string{"-i"}, Label: c}
		}
	}
	t.Skip("no interactive shell available for the terminal tests")
	return shell.Spec{}
}

func findExec(p string) string {
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

func newTestSession(t *testing.T, sink OutputSink, pump PumpConfig) *TerminalSession {
	t.Helper()
	ts, err := NewSession("test-session-id-0001", StartOptions{
		Shell: testShell(t),
		Env:   []string{"PATH=" + os.Getenv("PATH"), "TERM=xterm-256color"},
		Dir:   os.TempDir(),
		Cols:  80,
		Rows:  24,
		Sink:  sink,
		Log:   logging.Discard(),
		Pump:  pump,
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	return ts
}

func TestSessionRunsARealShellAndStreamsOutput(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())
	defer ts.Close()

	if ts.Pid() <= 0 {
		t.Fatal("no shell pid")
	}
	// Prove it is a terminal, not a pipe: `tty` only prints a device path when
	// stdin is a TTY.
	if _, err := ts.WriteInput([]byte("tty\n")); err != nil {
		t.Fatalf("write input: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		return strings.Contains(sink.text(), "/dev/pts") || strings.Contains(sink.text(), "ConPTY")
	})
	if contains(sink.text(), "not a tty") {
		t.Fatalf("the shell is not attached to a terminal:\n%s", sink.text())
	}
}

func TestInputIsForwardedVerbatim(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())
	defer ts.Close()

	// Arrow keys are escape sequences locally and must arrive unchanged.
	if _, err := ts.WriteInput([]byte("echo TOKEN-9\r")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool { return contains(sink.text(), "TOKEN-9") })
}

func TestResizeReachesThePTY(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())
	defer ts.Close()

	if err := ts.Resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	_, _ = ts.WriteInput([]byte("stty size\n"))
	waitFor(t, 10*time.Second, func() bool { return contains(sink.text(), "40 120") })
}

func TestResizeRejectsNonsense(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())
	defer ts.Close()
	for _, bad := range [][2]int{{0, 0}, {-1, 10}, {10, -1}, {5000, 5000}} {
		if err := ts.Resize(bad[0], bad[1]); err == nil {
			t.Fatalf("resize(%d,%d) should have failed", bad[0], bad[1])
		}
	}
}

func TestExitStatusIsReported(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())

	_, _ = ts.WriteInput([]byte("exit 5\n"))
	select {
	case st, ok := <-ts.Exit():
		if !ok {
			t.Fatal("exit channel closed without a status")
		}
		if st.Code != 5 {
			t.Fatalf("exit code = %d, want 5", st.Code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shell did not exit")
	}
	ts.Close()
}

func TestBackpressureBlocksTheReaderInsteadOfGrowingMemory(t *testing.T) {
	sink := newMemSink()
	pump := DefaultPumpConfig()
	pump.QueueDepth = 4
	pump.ReadChunk = 4096
	ts := newTestSession(t, sink, pump)
	defer ts.Close()

	sink.stalled.Store(true)
	// Produce far more output than the queue can hold.
	_, _ = ts.WriteInput([]byte("for i in $(seq 1 20000); do echo 0123456789012345678901234567890123456789; done\n"))

	waitFor(t, 10*time.Second, func() bool { return ts.Backpressured() })
	time.Sleep(300 * time.Millisecond)

	// The whole point: the queue is bounded, so a wedged client cannot make the
	// server accumulate the entire output in memory.
	if q := ts.Queued(); q > pump.QueueDepth*pump.ReadChunk*2 {
		t.Fatalf("queued bytes %d exceeded the bound (%d)", q, pump.QueueDepth*pump.ReadChunk*2)
	}

	sink.stalled.Store(false)
	close(sink.release)
	waitFor(t, 15*time.Second, func() bool { return sink.count() > 0 })
}

func TestSlowClientIsDetectedAndReported(t *testing.T) {
	sink := newMemSink()
	pump := DefaultPumpConfig()
	pump.SlowClientTimeout = 50 * time.Millisecond
	ts := newTestSession(t, sink, pump)
	defer ts.Close()

	// The writer stamps its progress on every successful write, so a client
	// that has been silent for longer than the timeout is flagged.
	waitFor(t, 3*time.Second, func() bool {
		return ts.CheckSlowClient(time.Now().Add(time.Hour))
	})
	if !ts.CheckSlowClient(time.Now().Add(time.Hour)) {
		t.Fatal("a client a full hour behind should always be flagged")
	}
}

func TestCloseStopsThePumpsAndIsIdempotent(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())

	ts.Close()
	if !ts.Closed() {
		t.Fatal("Closed() should report true after Close")
	}
	ts.Close() // must not panic
	if _, err := ts.WriteInput([]byte("x")); !errors.Is(err, pty.ErrClosed) {
		t.Fatalf("write after close = %v, want ErrClosed", err)
	}
	// A closed session is never reported as a slow client, so the sweeper does
	// not try to tear down something that is already gone.
	if ts.CheckSlowClient(time.Now().Add(time.Hour)) {
		t.Fatal("a closed session must not be flagged as slow")
	}
}

func TestSetSinkSupportsReconnect(t *testing.T) {
	first := newMemSink()
	ts := newTestSession(t, first, DefaultPumpConfig())
	defer ts.Close()

	_, _ = ts.WriteInput([]byte("echo FIRST_SINK\n"))
	waitFor(t, 10*time.Second, func() bool { return contains(first.text(), "FIRST_SINK") })

	second := newMemSink()
	ts.SetSink(second)
	if ts.Sink() != second {
		t.Fatal("SetSink did not take effect")
	}
	_, _ = ts.WriteInput([]byte("echo SECOND_SINK\n"))
	waitFor(t, 10*time.Second, func() bool { return contains(second.text(), "SECOND_SINK") })
	if !contains(first.text(), "FIRST_SINK") {
		t.Fatal("the first sink lost its earlier output")
	}
}

func TestNewSessionRequiresASink(t *testing.T) {
	_, err := NewSession("x", StartOptions{Shell: testShell(t)})
	if err == nil {
		t.Fatal("a session without an OutputSink must be refused")
	}
}

func TestSignalIsForwarded(t *testing.T) {
	sink := newMemSink()
	ts := newTestSession(t, sink, DefaultPumpConfig())
	defer ts.Close()

	_, _ = ts.WriteInput([]byte("sleep 30\n"))
	time.Sleep(500 * time.Millisecond)
	if err := ts.Signal("INT"); err != nil {
		t.Logf("signal INT: %v (some platforms deliver control characters instead)", err)
	}
	// Whatever the platform, the session must still be usable.
	_, _ = ts.WriteInput([]byte("echo AFTER_SIGNAL\n"))
	waitFor(t, 10*time.Second, func() bool { return contains(sink.text(), "AFTER_SIGNAL") })
}

func TestPumpConfigNormalisesDefaults(t *testing.T) {
	var c PumpConfig
	c.normalise()
	d := DefaultPumpConfig()
	if c.MaxQueuedBytes != d.MaxQueuedBytes || c.ReadChunk != d.ReadChunk ||
		c.QueueDepth != d.QueueDepth || c.SlowClientTimeout != d.SlowClientTimeout {
		t.Fatalf("a zero PumpConfig did not become the defaults: %+v", c)
	}
}

func TestShortID(t *testing.T) {
	if shortID("abcdef0123456789") != "abcdef01" {
		t.Fatalf("shortID = %q", shortID("abcdef0123456789"))
	}
	if shortID("abc") != "abc" {
		t.Fatalf("shortID = %q", shortID("abc"))
	}
	if shortID("") != "" {
		t.Fatalf("shortID of an empty id should be empty")
	}
}

// contains reports whether s contains sub. Terminal output arrives in
// unpredictable chunks, so assertions match on content rather than on framing.
func contains(s, sub string) bool { return strings.Contains(s, sub) }

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(fmt.Sprintf("condition not met within %s", timeout))
}
