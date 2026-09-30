//go:build windows

package client

import "os"

// Windows has no SIGWINCH. Console resize events surface through
// SIGWINCH-equivalent polling in the size watcher, so the client sends the
// initial size and then relies on the periodic refresh below.
func signalWinch() os.Signal { return os.Interrupt }

func signalInterrupt() os.Signal { return os.Interrupt }
func signalTerminate() os.Signal { return os.Kill }
