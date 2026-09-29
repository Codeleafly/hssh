//go:build windows

package pty

// On Windows the child is terminated explicitly on close, so there is no
// signal-0 liveness probe; the test skips the check instead.
const signalZero = unsupportedSignal{}

type unsupportedSignal struct{}

func (unsupportedSignal) String() string { return "unsupported" }
func (unsupportedSignal) Signal()        {}
