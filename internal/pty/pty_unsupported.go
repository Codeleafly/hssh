//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix || windows)

package pty

import (
	"errors"
	"os/exec"
	"strings"
	"time"
)

// On platforms without a native pseudo-terminal (plan9, js/wasm, bare-metal
// targets) HSSH refuses to fake a terminal. Returning an error here is
// deliberate: a pipe-based "terminal" would break isatty, job control, colours
// and every full-screen program, which is worse than not starting.
const supported = false

func openPlatform(opts OpenOptions) (PTY, error) {
	return nil, errors.New("pty: no native pseudo-terminal support on this platform")
}

func platformSignal(PTY, string) error { return errors.New("pty: unsupported") }

func platformKillAndWait(PTY, time.Duration) {}

func platformWait(PTY) ExitStatus { return ExitStatus{Code: -1, Err: errors.New("pty: unsupported")} }

func fileExists(string) bool { return false }

func which(name string) (string, bool) {
	if strings.ContainsRune(name, '/') {
		return name, false
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}
