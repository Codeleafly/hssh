package server

import (
	"sync"
	"sync/atomic"

	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/wsx"
)

// wsSink adapts a WebSocket connection to terminal.OutputSink.
//
// Terminal output is put on a bounded queue rather than written inline. The
// PTY reader must never be able to grow memory without limit because a client
// stopped reading, and it must never block for long either. So:
//
//   - WriteOutput enqueues and returns. A full queue means the client is
//     genuinely behind; the reader goroutine blocks on the channel send, which
//     back-pressures into the PTY (and from there into the shell).
//   - A single writer goroutine owns the socket, satisfying gorilla's
//     one-writer rule and removing any chance of interleaved frames.
type wsSink struct {
	conn *wsx.Conn

	queue   chan []byte
	stop    chan struct{}
	stopped atomic.Bool
	once    sync.Once
	stopOnce sync.Once
	wg      sync.WaitGroup

	queued atomic.Int64
	// maxFrame guards against a peer that somehow queues an enormous chunk.
	maxFrame int64
}

func newWSSink(conn *wsx.Conn, maxFrame int64) *wsSink {
	s := &wsSink{
		conn:     conn,
		queue:    make(chan []byte, 64),
		stop:     make(chan struct{}),
		maxFrame: maxFrame,
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// WriteOutput queues raw terminal bytes. Terminal data is already framed by the
// protocol, so nothing here re-encodes it.
func (s *wsSink) WriteOutput(payload []byte) error {
	if s.stopped.Load() {
		return errClientGone
	}
	if int64(len(payload)) > s.maxFrame {
		// Split rather than drop: a partial frame is still a partial frame the
		// client can use, and losing bytes would corrupt the screen.
		const maxChunk = 64 << 10
		for off := 0; off < len(payload); off += maxChunk {
			end := off + maxChunk
			if end > len(payload) {
				end = len(payload)
			}
			if err := s.enqueue(payload[off:end]); err != nil {
				return err
			}
		}
		return nil
	}
	return s.enqueue(payload)
}

func (s *wsSink) enqueue(b []byte) error {
	cp := make([]byte, len(b))
	copy(cp, b)
	s.queued.Add(int64(len(cp)))
	select {
	case s.queue <- cp:
		return nil
	case <-s.stop:
		s.queued.Add(-int64(len(cp)))
		return errClientGone
	}
}

// Buffered reports queued bytes, used by the slow-client detector.
func (s *wsSink) Buffered() int { return int(s.queued.Load()) }

// SendControl writes a JSON control message. It jumps the queue so a resize
// acknowledgement or an exit notice is never stuck behind a megabyte of
// `cat` output.
func (s *wsSink) SendControl(msg any) error {
	b, err := protocol.EncodeControl(msg)
	if err != nil {
		return err
	}
	return s.conn.WriteText(b)
}

// closeStop unblocks enqueuers without waiting. It is safe to call from the
// writer goroutine itself.
func (s *wsSink) closeStop() {
	s.stopOnce.Do(func() {
		s.stopped.Store(true)
		close(s.stop)
	})
}

// Close stops the writer goroutine. The connection itself is closed by the
// session, not here.
func (s *wsSink) Close() {
	s.closeStop()
	s.once.Do(func() {
		s.wg.Wait()
	})
}

func (s *wsSink) run() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		case chunk := <-s.queue:
			s.queued.Add(-int64(len(chunk)))
			if err := s.conn.WriteBinary(chunk); err != nil {
				// The peer is gone or wedged. Unblock any enqueuers so
				// TerminalSession.Close / writePump do not hang; the session
				// layer notices via the read loop and tears everything down.
				s.closeStop()
				return
			}
		}
	}
}
