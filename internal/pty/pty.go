// Package pty provides real pseudo-terminal support across platforms.
//
// The exported API is platform independent; unix and windows live in
// pty_unix.go / pty_windows.go. The terminal (shell) actually started is a
// genuine interactive process running on a genuine TTY device, so `isatty`
// succeeds inside the shell and full-screen programs (vim, top, htop, less)
// work exactly as they would over SSH.
package pty

import (
	"errors"
	"io"
)

// ErrClosed is returned by operations on a PTY that has already been closed.
var ErrClosed = errors.New("pty: closed")

// ErrUnknownSignal is returned for a signal name the platform cannot deliver.
type ErrUnknownSignal string

func (e ErrUnknownSignal) Error() string {
	return "pty: unsupported signal: " + string(e)
}

// Winsize is a terminal window size in character cells.
type Winsize struct {
	Cols uint16
	Rows uint16
	X    uint16 // pixel width, 0 when unknown
	Y    uint16 // pixel height, 0 when unknown
}

// PTY is a live pseudo-terminal pair: a master side (held by the server) and a
// slave side that the child process is attached to.
type PTY interface {
	io.ReadWriteCloser

	// Resize changes the window size reported to the attached process via
	// TIOCSWINSZ (and, on Unix, delivers SIGWINCH).
	Resize(ws Winsize) error

	// Pid returns the process id of the attached child, or 0 if unknown.
	Pid() int

	// Name returns the slave device path (Unix) or ConPTY handle info.
	Name() string

	// IsWindows reports whether the returned pty is a Windows ConPTY.
	IsWindows() bool
}

// OpenOptions configures PTY allocation and process spawn.
type OpenOptions struct {
	// Command is the executable to run, with Args (argv[0] is Command).
	Command string
	// Args are the arguments after argv[0].
	Args []string
	// Env is the complete child environment. Callers should build it from the
	// server environment, not inherit implicitly, so sessions stay isolated.
	Env []string
	// Dir is the working directory for the child process.
	Dir string

	Winsize Winsize

	// EnvExtra is merged on top of Env (child wins on conflict). It is where
	// TERM and other per-session variables belong.
	EnvExtra map[string]string

	// OnUnix and OnWindows override the executable lookup order.
	OnUnix    []string
	OnWindows []string
}

// Open allocates a PTY and starts the configured process inside it.
//
// On Unix the implementation uses posix_openpt/grantpt/unlockpt + fork/exec
// with the slave as stdin/stdout/stderr and a controlling terminal.
//
// On Windows it uses ConPTY (CreatePseudoConsole + InitializeProcThreadAttributeList
// with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE), so conhost.exe is a real console.
func OpenPTY(opts OpenOptions) (PTY, error) {
	if !Supported() {
		return nil, errors.New("pty: pseudo-terminals are not supported on this platform")
	}
	return openPlatform(opts.withDefaults())
}

// Supported reports whether real PTY allocation is available on this platform.
func Supported() bool { return supported }

// lookup finds the first existing path from candidates.
func lookup(candidates []string) (string, bool) {
	for _, c := range candidates {
		if fileExists(c) {
			return c, true
		}
	}
	return "", false
}

func (o OpenOptions) withDefaults() OpenOptions {
	if o.Winsize.Cols == 0 {
		o.Winsize.Cols = 80
	}
	if o.Winsize.Rows == 0 {
		o.Winsize.Rows = 24
	}
	if o.Env == nil {
		o.Env = []string{}
	}
	return o
}

// mergeEnv merges EnvExtra over Env. The extras go last because Go's
// environment de-duplication keeps the final definition of a key, so appending
// them at the end is what makes the per-session TERM and HSSH_* values win
// over the host's defaults.
func (o OpenOptions) mergeEnv() []string {
	if len(o.EnvExtra) == 0 {
		return o.Env
	}
	out := make([]string, 0, len(o.Env)+len(o.EnvExtra))
	out = append(out, o.Env...)
	for k, v := range o.EnvExtra {
		out = append(out, k+"="+v)
	}
	return out
}
