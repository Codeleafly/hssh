// Package shell resolves the real interactive shell to run inside a PTY and
// builds the per-session environment. Keeping this separate from pty means the
// protocol layer never has to know about bash vs PowerShell.
package shell

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Spec describes a shell that can be launched inside a PTY.
type Spec struct {
	// Path is the resolved executable.
	Path string
	// Args are the arguments passed after argv[0]. Interactive login shells get
	// their login flag so the user's profile is loaded.
	Args []string
	// Label is what the session manager displays.
	Label string
}

// ErrNotFound is returned when no usable shell exists.
var ErrNotFound = errors.New("shell: no interactive shell found")

// DefaultEnv builds the environment for a session from the server process
// environment, filtered to an allowlist plus explicitly requested variables.
//
// Filtering matters for isolation and for not leaking HSSH's own secrets (such
// as a --password flag value) into every remote shell.
func DefaultEnv(extra map[string]string) []string {
	allowed := map[string]bool{
		"HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "PWD": true,
		"PATH": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true,
		"TERM": true, "COLORTERM": true, "EDITOR": true, "VISUAL": true, "PAGER": true,
		"HOSTNAME": true, "OSTYPE": true, "MACHTYPE": true, "DISPLAY": true,
		"XDG_RUNTIME_DIR": true, "XDG_SESSION_TYPE": true, "XDG_SEAT": true,
		"WT_SESSION": true, "ConEmuPID": true, "TERMINAL_EMULATOR": true,
		"MSYSTEM": true, "PROCESSOR_ARCHITECTURE": true, "HSSH_SESSION": true,
	}

	// Build a map so the session's own values replace the host's instead of
	// being appended as a duplicate. Two definitions of the same key make the
	// child's environment depend on execve implementation details.
	env := make(map[string]string, 32)
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if k := kv[:i]; allowed[k] {
			env[k] = kv[i+1:]
		}
	}
	// Anything explicitly requested (session TERM, HSSH_*, custom vars).
	for k, v := range extra {
		env[k] = v
	}

	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	// A stable order keeps the environment reproducible, which matters when
	// comparing two sessions' environments.
	sort.Strings(out)
	return out
}

// HomeDir returns the user's home directory with a sensible fallback, used as
// the default session working directory.
func HomeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		if h := os.Getenv("USERPROFILE"); h != "" {
			return h
		}
	}
	return "."
}

// resolveUnix finds an interactive login-capable unix shell.
func resolveUnix() (Spec, error) {
	// 1. Explicit override from the environment.
	candidates := []string{}
	if s := os.Getenv("HSSH_SHELL"); s != "" {
		candidates = append(candidates, s)
	}
	// 2. $SHELL, as the specification requires.
	if s := os.Getenv("SHELL"); s != "" {
		candidates = append(candidates, s)
	}
	// 3. Known shells, most capable first, so the user still gets a good shell
	//    when $SHELL is unset or points at something missing.
	candidates = append(candidates,
		"/bin/bash", "/usr/bin/bash",
		"/bin/zsh", "/usr/bin/zsh",
		"/usr/bin/fish", "/usr/local/bin/fish",
		"/bin/ash", "/bin/dash", "/bin/sh",
	)

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		base := filepath.Base(c)
		var args []string
		if isInteractiveShell(base) {
			// Login shell: sources profile. -i keeps it interactive when stdin
			// is a TTY (it always is, inside the PTY).
			args = []string{"-l", "-i"}
		}
		return Spec{Path: c, Args: args, Label: base}, nil
	}
	return Spec{}, ErrNotFound
}

func isInteractiveShell(base string) bool {
	switch base {
	case "bash", "zsh", "ksh", "mksh", "fish", "ash", "dash", "sh", "tcsh", "csh":
		return true
	}
	return false
}

// envBool reports whether an env var is truthy.
func envBool(name string) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
