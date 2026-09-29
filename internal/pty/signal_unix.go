//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package pty

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// platformSignal maps a protocol signal name to a real Unix signal.
var platformSignals = map[string]syscall.Signal{
	"INT":   syscall.SIGINT,
	"TERM":  syscall.SIGTERM,
	"HUP":   syscall.SIGHUP,
	"QUIT":  syscall.SIGQUIT,
	"KILL":  syscall.SIGKILL,
	"TSTP":  syscall.SIGTSTP,
	"CONT":  syscall.SIGCONT,
	"USR1":  syscall.SIGUSR1,
	"USR2":  syscall.SIGUSR2,
	"WINCH": syscall.SIGWINCH,
}

func platformSignal(p PTY, name string) error {
	sig, ok := platformSignals[name]
	if !ok {
		return ErrUnknownSignal(name)
	}
	up, ok := p.(*unixPTY)
	if !ok {
		return ErrClosed
	}
	return up.Terminate(sig)
}

// platformKill force-terminates the child. Reaping stays the job of
// platformWait so it happens exactly once.
func platformKill(p PTY) {
	up, ok := p.(*unixPTY)
	if !ok {
		return
	}
	up.mu.Lock()
	proc := up.cmdProcess()
	up.mu.Unlock()
	if proc != nil {
		_ = proc.Signal(syscall.SIGHUP)
		_ = proc.Kill()
	}
}

func platformWait(p PTY) ExitStatus {
	up, ok := p.(*unixPTY)
	if !ok {
		return ExitStatus{Err: ErrClosed}
	}
	ee, err := up.Wait()
	if err != nil {
		return ExitStatus{Code: -1, Err: err}
	}
	if ee == nil {
		return ExitStatus{Code: 0}
	}
	st := ee.ExitCode()
	// WaitStatus reports signal death as exit code -1 with Signal set.
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return ExitStatus{Code: 128 + int(ws.Signal()), Signal: ws.Signal().String()}
	}
	if st < 0 {
		st = 0
	}
	return ExitStatus{Code: st}
}

// which resolves an executable name against PATH. Used by the shell provider.
func which(name string) (string, bool) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, fileExists(name)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}
