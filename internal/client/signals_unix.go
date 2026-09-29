//go:build !windows

package client

import (
	"os"
	"syscall"
)

// The local terminal generates SIGWINCH on resize and SIGINT/SIGTERM are
// delivered to the process. While raw mode is active Ctrl+C is a byte, not a
// signal, so these only fire on an external `kill`.
func signalWinch() os.Signal     { return syscall.SIGWINCH }
func signalInterrupt() os.Signal { return syscall.SIGINT }
func signalTerminate() os.Signal { return syscall.SIGTERM }
