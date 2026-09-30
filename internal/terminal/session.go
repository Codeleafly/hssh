// Package terminal hosts the server-side TerminalSession: a real PTY with a
// real shell inside it, plus the pumps that move bytes between that PTY and
// the WebSocket connection.
//
// The three invariants this file exists to enforce:
//
//  1. Output is never dropped and never buffered without bound. If the client
//     cannot keep up, the PTY reader blocks, the kernel PTY buffer fills, and
//     the writing process blocks too. That is real backpressure, exactly like a
//     slow SSH link.
//  2. A client that is not merely slow but wedged gets disconnected rather than
//     being allowed to grow the server's memory without limit.
//  3. The PTY and the child process are released exactly once, on every exit
//     path: shell exit, client disconnect, idle timeout, server shutdown.
package terminal

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/pty"
	"github.com/hssh/hssh/internal/shell"
)

// OutputSink receives data produced by the PTY. Implementations must be safe
// for concurrent use.
type OutputSink interface {
	// WriteOutput queues raw terminal bytes. It must not block indefinitely.
	WriteOutput(payload []byte) error
	// SendControl sends a JSON control message.
	SendControl(msg any) error
	// Buffered reports how many bytes are still queued for this sink.
	Buffered() int
}

// PumpConfig tunes the output path.
type PumpConfig struct {
	// MaxQueuedBytes is the hard ceiling on unflushed terminal output. Once it
	// is reached the reader stops reading from the PTY.
	MaxQueuedBytes int
	// ReadChunk is the PTY read size. Large enough to keep syscall overhead
	// low, small enough to keep interactivity sharp.
	ReadChunk int
	// QueueDepth is the number of buffered chunks (each ReadChunk bytes).
	QueueDepth int
	// SlowClientTimeout is how long the writer may stay behind before the
	// client is declared wedged and the session is terminated.
	SlowClientTimeout time.Duration
	// WriteTimeout bounds a single WebSocket write.
	WriteTimeout time.Duration
}

// DefaultPumpConfig returns tuned defaults. QueueDepth * ReadChunk ~=
// MaxQueuedBytes so --output-buffer bounds memory.
func DefaultPumpConfig() PumpConfig {
	return PumpConfig{
		MaxQueuedBytes:    4 << 20, // 4 MiB
		ReadChunk:         32 << 10,
		QueueDepth:        128, // 128*32K = 4M
		SlowClientTimeout: 30 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

func (c *PumpConfig) normalise() {
	if c.MaxQueuedBytes <= 0 {
		c.MaxQueuedBytes = 4 << 20
	}
	if c.ReadChunk <= 0 {
		c.ReadChunk = 32 << 10
	}
	if c.QueueDepth <= 0 {
		// Derive the queue depth from the byte ceiling so --output-buffer
		// actually bounds memory: depth * chunk ~= MaxQueuedBytes.
		depth := c.MaxQueuedBytes / c.ReadChunk
		if depth < 4 {
			depth = 4
		}
		if depth > 256 {
			depth = 256
		}
		c.QueueDepth = depth
	}
	if c.SlowClientTimeout <= 0 {
		c.SlowClientTimeout = 30 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
}

// StartOptions configures a new TerminalSession.
type StartOptions struct {
	// Shell is the resolved shell to launch.
	Shell shell.Spec
	// Env is the base environment for the child.
	Env []string
	// EnvExtra is merged on top (TERM, HSSH_*, ...).
	EnvExtra map[string]string
	// Dir is the initial working directory.
	Dir string

	Cols int
	Rows int

	Sink OutputSink
	Log  *logging.Logger
	Pump PumpConfig

	// OnCwd is called from the pump goroutine whenever the shell announces
	// a new working directory (OSC 7 shell integration). It may be nil, in
	// which case output is not scanned at all.
	OnCwd func(dir string)
}

// TerminalSession is one client bound to one PTY and one shell process.
type TerminalSession struct {
	id  string
	pty *pty.Handle

	// sinkMu guards sink so a reconnecting client can take over the session
	// without racing the pumps that are already writing to the old socket.
	sinkMu sync.RWMutex
	sink   OutputSink

	log    *logging.Logger
	pump   PumpConfig
	shell  shell.Spec
	closed atomic.Bool

	// onCwd receives live directory announcements; osc7 scans the output.
	onCwd func(string)
	osc7  osc7Scanner

	// queued counts bytes waiting to be written to the sink.
	queued atomic.Int64
	// chunks is the bounded write queue.
	chunks chan []byte

	// lastWrite tracks writer progress for slow-client detection.
	lastWrite atomic.Int64
	// backpressured is set while the reader is blocked on a full queue.
	backpressured atomic.Bool

	closeOnce sync.Once
	stop      chan struct{}
	writerWG  sync.WaitGroup
	readerWG  sync.WaitGroup
	exitOnce  sync.Once
	exit      chan pty.ExitStatus
}

// NewSession allocates the PTY, starts the shell inside it and wires up the
// pumps. On any failure everything already created is released before return.
func NewSession(id string, opts StartOptions) (*TerminalSession, error) {
	if !pty.Supported() {
		return nil, errors.New("terminal: this platform has no pseudo-terminal support")
	}
	opts.Pump.normalise()
	log := opts.Log
	if log == nil {
		log = logging.Discard()
	}
	if opts.Sink == nil {
		return nil, errors.New("terminal: OutputSink is required")
	}

	h, err := pty.Open(pty.OpenOptions{
		Command:  opts.Shell.Path,
		Args:     opts.Shell.Args,
		Env:      opts.Env,
		Dir:      opts.Dir,
		EnvExtra: opts.EnvExtra,
		Winsize:  pty.Winsize{Cols: uint16(opts.Cols), Rows: uint16(opts.Rows)},
	})
	if err != nil {
		return nil, fmt.Errorf("terminal: could not allocate a PTY: %w", err)
	}

	s := &TerminalSession{
		id:     id,
		pty:    h,
		sink:   opts.Sink,
		log:    log,
		pump:   opts.Pump,
		shell:  opts.Shell,
		onCwd:  opts.OnCwd,
		chunks: make(chan []byte, opts.Pump.QueueDepth),
		stop:   make(chan struct{}),
		exit:   make(chan pty.ExitStatus, 1),
	}
	s.lastWrite.Store(time.Now().UnixNano())

	s.writerWG.Add(1)
	go s.writePump()

	s.readerWG.Add(1)
	go s.readPump()

	// Watcher reports the shell's exit status exactly once, whoever gets there
	// first (shell exit, client disconnect, timeout).
	go func() {
		st, _ := h.Wait()
		s.exitOnce.Do(func() { s.exit <- st })
		close(s.exit)
	}()

	log.Debug("pty created",
		logging.F("session", shortID(id)),
		logging.F("shell", opts.Shell.Label),
		logging.F("pid", h.Pid()),
		logging.F("tty", h.Name()),
		logging.F("size", fmt.Sprintf("%dx%d", opts.Cols, opts.Rows)),
	)
	return s, nil
}

// ID returns the session id.
func (s *TerminalSession) ID() string { return s.id }

// Sink returns the current output sink.
func (s *TerminalSession) Sink() OutputSink {
	s.sinkMu.RLock()
	defer s.sinkMu.RUnlock()
	return s.sink
}

// SetSink swaps the output sink, which is how a reconnecting client takes over
// an existing session. In-flight output queued for the previous socket is
// dropped, because that socket's peer is the one that just went away.
func (s *TerminalSession) SetSink(sink OutputSink) {
	s.sinkMu.Lock()
	old := s.sink
	s.sink = sink
	s.sinkMu.Unlock()
	if c, ok := old.(interface{ Close() }); ok {
		c.Close()
	}
}

// Pid returns the shell process id.
func (s *TerminalSession) Pid() int { return s.pty.Pid() }

// ShellLabel returns the shell name for the session table.
func (s *TerminalSession) ShellLabel() string { return s.shell.Label }

// Backpressured reports whether the output queue is currently full, which
// means the client is slower than the shell.
func (s *TerminalSession) Backpressured() bool { return s.backpressured.Load() }

// Exit returns a channel that yields the shell's exit status and then closes.
func (s *TerminalSession) Exit() <-chan pty.ExitStatus { return s.exit }

// readPump is the PTY -> client direction.
func (s *TerminalSession) readPump() {
	defer s.readerWG.Done()
	buf := make([]byte, s.pump.ReadChunk)

	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			// Live cwd tracking (OSC 7) observes the output without
			// touching a single byte of it.
			if s.onCwd != nil {
				if dir, changed := s.osc7.observe(buf[:n]); changed {
					s.onCwd(dir)
				}
			}
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			s.queued.Add(int64(n))
			// Blocking here is the backpressure. While this send blocks we are
			// not reading the PTY, so the kernel buffer fills and the shell
			// blocks on its own write(). Nothing is ever dropped.
			s.backpressured.Store(true)
			select {
			case s.chunks <- chunk:
			case <-s.stop:
				s.backpressured.Store(false)
				s.queued.Add(-int64(n))
				return
			}
			s.backpressured.Store(false)
		}
		if err != nil {
			// EIO on a PTY master is the normal "child is gone" signal.
			if !errors.Is(err, io.EOF) && !isPTYHangup(err) {
				s.log.Debug("pty read ended",
					logging.F("session", shortID(s.id)),
					logging.F("reason", err.Error()),
				)
			}
			return
		}
	}
}

// writePump is the queue -> WebSocket direction.
func (s *TerminalSession) writePump() {
	defer s.writerWG.Done()
	for {
		select {
		case <-s.stop:
			return
		case chunk := <-s.chunks:
			// Release the queue slot before the (slow) network write so the
			// reader can refill while we are still transmitting.
			s.queued.Add(-int64(len(chunk)))
			frame := protocol.EncodePayload(protocol.PayloadOutput, chunk)
			err := s.Sink().WriteOutput(frame)
			s.lastWrite.Store(time.Now().UnixNano())
			if err != nil {
				s.log.Debug("output write failed",
					logging.F("session", shortID(s.id)),
					logging.F("reason", err.Error()),
				)
				s.Close()
				return
			}
		}
	}
}

// WriteInput forwards client keystrokes into the PTY master.
//
// The bytes are written verbatim: escape sequences for arrows, function keys,
// bracketed paste markers and control characters all reach the remote line
// editor exactly as the local terminal produced them. No translation layer
// sits in the way.
func (s *TerminalSession) WriteInput(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, pty.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	return s.pty.Write(b)
}

// Resize changes the PTY window size, which the kernel reports to the shell and
// follows with SIGWINCH. Full-screen programs depend on it.
func (s *TerminalSession) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return errors.New("terminal: invalid window size")
	}
	if cols > 1000 || rows > 1000 {
		return fmt.Errorf("terminal: window size %dx%d out of range", cols, rows)
	}
	return s.pty.Resize(pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Signal delivers a named signal to the shell.
func (s *TerminalSession) Signal(name string) error { return s.pty.Signal(name) }

// Close tears the session down: the PTY master is closed, the child is hung up
// and then killed if it lingers, and both pumps are stopped. It is safe to call
// from several goroutines and from the close hook of the session manager.
func (s *TerminalSession) Close() {
	s.closeOnce.Do(func() {
		if !s.closed.CompareAndSwap(false, true) {
			return
		}
		s.log.Debug("pty closing", logging.F("session", shortID(s.id)))

		// Stop the writer first so a blocked network write is abandoned, then
		// close the master so the child gets its hangup.
		// Close the sink first: writePump may be blocked inside
		// Sink().WriteOutput (bounded queue full on a wedged client) and
		// would otherwise never observe stop.
		if c, ok := s.Sink().(interface{ Close() }); ok {
			c.Close()
		}
		close(s.stop)

		err := s.pty.Close()
		if err != nil {
			s.log.Debug("pty close error",
				logging.F("session", shortID(s.id)),
				logging.F("reason", err.Error()),
			)
		}

		// Close() on the handle owns the single reaper, so the shell is always
		// waited for and can never become a zombie.
		if st := <-s.exit; true {
			s.log.Debug("shell exited",
				logging.F("session", shortID(s.id)),
				logging.F("code", st.Code),
				logging.F("signal", st.Signal),
			)
		}

		s.writerWG.Wait()
		s.readerWG.Wait()
		s.log.Debug("pty closed", logging.F("session", shortID(s.id)))
	})
}

// Closed reports whether Close has run.
func (s *TerminalSession) Closed() bool { return s.closed.Load() }

// CheckSlowClient returns true when the writer has been behind for longer than
// the configured timeout AND output is actually backed up. An idle session
// with an empty queue is healthy, not slow: lastWrite goes stale whenever the
// shell produces no output, and killing on that alone disconnects every idle
// client after SlowClientTimeout.
func (s *TerminalSession) CheckSlowClient(now time.Time) bool {
	if s.closed.Load() {
		return false
	}
	if s.queued.Load() == 0 && !s.backpressured.Load() {
		return false
	}
	behind := now.Sub(time.Unix(0, s.lastWrite.Load()))
	if behind > s.pump.SlowClientTimeout {
		s.log.Warn("terminating slow client",
			logging.F("session", shortID(s.id)),
			logging.F("lag", behind.Truncate(time.Second).String()),
			logging.F("queued", s.queued.Load()),
		)
		return true
	}
	return false
}

// Queued returns the number of bytes waiting to be sent.
func (s *TerminalSession) Queued() int { return int(s.queued.Load()) }

func isPTYHangup(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		containsAny(msg, "input/output error", "device not configured", "bad file descriptor")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

// shortID renders a session id for logs and tables.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
