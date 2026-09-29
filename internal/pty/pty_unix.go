//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package pty

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

const supported = true

// unixPTY owns the master side of a Unix PTY pair plus the child process.
type unixPTY struct {
	master *os.File
	cmd    *exec.Cmd
	mu     sync.Mutex
	closed bool
}

// fileExists reports whether path is an existing, non-directory file.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !fi.IsDir()
}

func openPlatform(opts OpenOptions) (PTY, error) {
	bin := opts.Command
	if bin == "" {
		bin, _ = lookup(opts.OnUnix)
	}
	if bin == "" {
		return nil, errors.New("pty: no shell executable found")
	}

	cmd := exec.Command(bin, opts.Args...)
	// Env and Dir must be set before StartWithSize, which forks the child.
	cmd.Env = opts.mergeEnv()
	cmd.Dir = opts.Dir

	master, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: opts.Winsize.Cols,
		Rows: opts.Winsize.Rows,
		X:    opts.Winsize.X,
		Y:    opts.Winsize.Y,
	})
	if err != nil {
		return nil, err
	}
	// A PTY has no use for the extra pipes exec.Cmd would create; the slave is
	// stdin/stdout/stderr already. Keep stdin nil so a reader cannot deadlock.
	return &unixPTY{master: master, cmd: cmd}, nil
}

func (p *unixPTY) Read(b []byte) (int, error)  { return p.master.Read(b) }
func (p *unixPTY) Write(b []byte) (int, error) { return p.master.Write(b) }

// Resize issues TIOCSWINSZ, which makes the kernel both report the new size to
// the child and deliver SIGWINCH to its foreground process group.
func (p *unixPTY) Resize(ws Winsize) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return pty.Setsize(p.master, &pty.Winsize{
		Cols: ws.Cols,
		Rows: ws.Rows,
		X:    ws.X,
		Y:    ws.Y,
	})
}

func (p *unixPTY) Pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *unixPTY) Name() string    { return p.master.Name() }
func (p *unixPTY) IsWindows() bool { return false }

// Close drops the master fd. The kernel then sends SIGHUP to the slave's
// foreground process group, which is exactly what happens when a real terminal
// disappears.
func (p *unixPTY) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	return p.master.Close()
}

// Terminate signals the child process directly.
func (p *unixPTY) Terminate(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.cmd == nil || p.cmd.Process == nil {
		return ErrClosed
	}
	return p.cmd.Process.Signal(sig)
}

// cmdProcess returns the child process handle, or nil if there is none.
// Callers must hold p.mu.
func (p *unixPTY) cmdProcess() *os.Process {
	if p.cmd == nil {
		return nil
	}
	return p.cmd.Process
}

// Wait reaps the child and returns its exit error, if any.
func (p *unixPTY) Wait() (*exec.ExitError, error) {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()
	if cmd == nil {
		return nil, ErrClosed
	}
	err := cmd.Wait()
	if err == nil {
		return nil, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee, nil
	}
	return nil, err
}
