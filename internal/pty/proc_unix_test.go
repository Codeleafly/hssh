//go:build !windows

package pty

import "syscall"

const signalZero = syscall.Signal(0)
