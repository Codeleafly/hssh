//go:build windows

package client

import "os"

// Windows has no SIGWINCH. Console resize events surface through
// SIGWINCH-equivalent polling in the size watcher, so the client sends the
// initial size and then relies on the periodic refresh below.
func signalWinch() os.Signal { return os.Interrupt }

// pollResize is a synthetic signal tick used on Windows to re-check the
// console size, since there is no SIGWINCH.
var pollResize = func() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	go func() {
		for {
			ch <- os.Interrupt
		}
	}()
	return ch
}

func signalInterrupt() os.Signal { return os.Interrupt }
func signalTerminate() os.Signal { return os.Kill }
