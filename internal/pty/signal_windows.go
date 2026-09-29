//go:build windows

package pty

import (
	"os/exec"
	"strconv"
	"strings"
)

// platformSignals maps a protocol signal name to a Windows exit/termination
// code. Windows has no POSIX signals, so the client sends control characters as
// input bytes (ConPTY turns Ctrl+C into a console CTRL_C_EVENT) and only the
// explicit "terminate the shell" paths reach this table.
var platformSignals = map[string]int{
	"TERM": 1,
	"KILL": 1,
	"INT":  2,
	"QUIT": 3,
	"HUP":  1,
}

func platformSignal(p PTY, name string) error {
	code, ok := platformSignals[name]
	if !ok {
		return ErrUnknownSignal(name)
	}
	wp, ok := p.(*windowsPTY)
	if !ok {
		return ErrClosed
	}
	return wp.Terminate(code)
}

// platformKill force-terminates the child process. Reaping stays the job of
// platformWait.
func platformKill(p PTY) {
	if wp, ok := p.(*windowsPTY); ok {
		_ = wp.Terminate(1)
	}
}

func platformWait(p PTY) ExitStatus {
	wp, ok := p.(*windowsPTY)
	if !ok {
		return ExitStatus{Err: ErrClosed}
	}
	code := wp.ExitCode()
	if code < 0 {
		return ExitStatus{Code: -1, Err: ErrClosed}
	}
	return ExitStatus{Code: code}
}

func which(name string) (string, bool) {
	if strings.ContainsAny(name, `/\:`) {
		return name, fileExists(name)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

func itoa(v int) string { return strconv.Itoa(v) }
