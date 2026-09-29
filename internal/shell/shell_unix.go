//go:build !windows

package shell

import "strings"

// Resolve picks the shell for a new session.
//
// Precedence: explicit HSSH_SHELL env, then $SHELL, then a scan of well-known
// shells, then /bin/sh as the final fallback. The result is always a real
// interactive program, never a wrapper script.
func Resolve(override string) (Spec, error) {
	if override != "" {
		if _, err := statExec(override); err == nil {
			return Spec{
				Path:  override,
				Args:  argsFor(override),
				Label: labelFor(override),
			}, nil
		}
		// A bare name like "bash" must be looked up on PATH.
		if p, err := lookPath(override); err == nil {
			return Spec{Path: p, Args: argsFor(p), Label: labelFor(p)}, nil
		}
		return Spec{}, ErrNotFound
	}
	return resolveUnix()
}

func argsFor(path string) []string {
	if isInteractiveShell(baseOf(path)) {
		return []string{"-l", "-i"}
	}
	return nil
}

func labelFor(path string) string { return baseOf(path) }

func baseOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}
