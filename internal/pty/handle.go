package pty

import (
	"sync"
	"time"
)

// ExitStatus describes how the shell process ended.
type ExitStatus struct {
	Code   int
	Signal string
	// Err is non-nil when the process could not be waited on at all.
	Err error
}

// defaultGracePeriod is how long a shell gets to exit politely after the PTY
// master is closed before it is killed outright.
const defaultGracePeriod = 2 * time.Second

// Handle is the platform-neutral wrapper the rest of HSSH talks to. It hides
// the unix/windows split behind one stable surface and guarantees the child
// process is reaped exactly once.
type Handle struct {
	inner PTY

	waitOnce sync.Once
	waitDone chan struct{}
	status   ExitStatus

	closeOnce sync.Once
	closeErr  error
	closeMu   sync.Mutex
	closed    bool
}

// Open allocates a real PTY and starts the process described by opts inside it.
// The returned Handle is the master side; Read/Write move raw terminal bytes.
func Open(opts OpenOptions) (*Handle, error) {
	inner, err := OpenPTY(opts)
	if err != nil {
		return nil, err
	}
	return &Handle{inner: inner, waitDone: make(chan struct{})}, nil
}

// Read pulls bytes from the PTY master. After Close it returns ErrClosed
// rather than the platform's "file already closed", so callers can test for one
// sentinel on every OS.
func (h *Handle) Read(p []byte) (int, error) {
	if h.isClosed() {
		return 0, ErrClosed
	}
	return h.inner.Read(p)
}

// Write pushes bytes into the PTY master.
func (h *Handle) Write(p []byte) (int, error) {
	if h.isClosed() {
		return 0, ErrClosed
	}
	return h.inner.Write(p)
}

func (h *Handle) isClosed() bool {
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	return h.closed
}

func (h *Handle) Resize(ws Winsize) error { return h.inner.Resize(ws) }
func (h *Handle) Pid() int                { return h.inner.Pid() }
func (h *Handle) Name() string            { return h.inner.Name() }
func (h *Handle) IsWindows() bool         { return h.inner.IsWindows() }

// Close releases the master side and guarantees the child is reaped.
//
// Closing the master makes the kernel hang up the slave: the shell gets
// SIGHUP on Unix, or a console-close event on Windows. If it has not exited
// within the grace period it is killed. There is exactly one reaper goroutine
// (Wait), so the child can never become a zombie and Wait can never be called
// twice.
func (h *Handle) Close() error {
	h.closeOnce.Do(func() {
		h.closeMu.Lock()
		h.closed = true
		h.closeMu.Unlock()

		h.closeErr = h.inner.Close()

		// Single reaper. Everything else just waits on h.waitDone.
		go func() { _, _ = h.Wait() }()

		t := time.NewTimer(defaultGracePeriod)
		defer t.Stop()
		select {
		case <-h.waitDone:
		case <-t.C:
			platformKill(h.inner)
			<-h.waitDone
		}
	})
	return h.closeErr
}

// Signal delivers a named signal (INT, TERM, HUP, ...) to the shell process.
func (h *Handle) Signal(name string) error {
	h.closeMu.Lock()
	closed := h.closed
	h.closeMu.Unlock()
	if closed {
		return ErrClosed
	}
	return platformSignal(h.inner, name)
}

// Done returns a channel closed once the child has been reaped.
func (h *Handle) Done() <-chan struct{} { return h.waitDone }

// Wait reaps the child and returns its exit status. It is safe to call from
// multiple goroutines; only the first call blocks.
func (h *Handle) Wait() (ExitStatus, error) {
	h.waitOnce.Do(func() {
		h.status = platformWait(h.inner)
		close(h.waitDone)
	})
	<-h.waitDone
	return h.status, h.status.Err
}
