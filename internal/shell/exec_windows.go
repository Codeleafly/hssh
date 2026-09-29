//go:build windows

package shell

import "os/exec"

func statExec(p string) (string, error) { return exec.LookPath(p) }
func lookPath(p string) (string, error) { return exec.LookPath(p) }
func baseOfShim(p string) string        { return p }
