// Package terminal wraps local terminal control: raw mode, window size, and
// restoring the original state. Restoration is the important part — a client
// that leaves the user's shell in raw mode is a broken client, so every exit
// path goes through Restore, including panics and signals.
package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// ErrNotATerminal is returned when the given file has no terminal attached.
var ErrNotATerminal = errors.New("terminal: not a terminal (is HSSH running under a pipe?)")

// Size is a window size in character cells.
type Size struct {
	Cols int
	Rows int
}

// State holds the original terminal attributes so they can be put back
// verbatim.
type State struct {
	termios *term.State

	mu     sync.Mutex
	f      *os.File
	active bool
}

var (
	globalMu    sync.Mutex
	globalState *State
	globalDepth int
)

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// SizeOf returns the current window size of f.
func SizeOf(f *os.File) (Size, error) {
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return Size{}, err
	}
	return Size{Cols: w, Rows: h}, nil
}

// MakeRaw puts f into raw mode and returns a State that restores it.
//
// Raw mode is what an SSH client does: no line buffering, no canonical echo,
// no signal generation from the keyboard (so Ctrl+C travels to the remote shell
// as byte 0x03 instead of killing the local client), and every key press is
// delivered immediately.
func MakeRaw(f *os.File) (*State, error) {
	if !term.IsTerminal(int(f.Fd())) {
		return nil, ErrNotATerminal
	}
	old, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("terminal: raw mode: %w", err)
	}
	return &State{termios: old, f: f, active: true}, nil
}

// Restore puts the terminal back exactly as it was. It is idempotent.
func (s *State) Restore() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.termios == nil {
		return nil
	}
	err := term.Restore(int(s.f.Fd()), s.termios)
	s.active = false
	if err != nil {
		return fmt.Errorf("terminal: restore: %w", err)
	}
	return nil
}

// Active reports whether the state still needs restoring.
func (s *State) Active() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// EnterRaw switches the process-wide terminal (os.Stdin) to raw mode. Nested
// calls are reference counted so multiple components can each enter and leave
// safely.
func EnterRaw() (*State, error) {
	s, err := MakeRaw(os.Stdin)
	if err != nil {
		return nil, err
	}
	globalMu.Lock()
	if globalState == nil {
		globalState = s
	}
	globalDepth++
	globalMu.Unlock()
	return s, nil
}

// ReleaseRaw undoes one EnterRaw. The terminal is restored when the count
// reaches zero. Inner handles are discarded without touching the terminal:
// only the outermost state owns the restore.
func ReleaseRaw(s *State) {
	if s == nil {
		return
	}
	globalMu.Lock()
	globalDepth--
	if globalDepth <= 0 {
		globalDepth = 0
		sToRestore := globalState
		globalState = nil
		globalMu.Unlock()
		if sToRestore != nil {
			_ = sToRestore.Restore()
		}
		return
	}
	globalMu.Unlock()
}

// RestoreNow force-restores the process terminal regardless of the refcount.
// It is called from signal handlers and the panic path.
func RestoreNow() {
	globalMu.Lock()
	s := globalState
	globalDepth = 0
	globalMu.Unlock()
	if s != nil {
		_ = s.Restore()
	}
}

// IsRawActive reports whether the process terminal is currently in raw mode.
func IsRawActive() bool {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalDepth > 0 && globalState != nil
}

// WriteTo writes raw bytes to the terminal, bypassing any Go-side buffering.
func WriteTo(w io.Writer, b []byte) (int, error) { return w.Write(b) }
