//go:build windows

package shell

import (
	"os"
	"path/filepath"
	"strings"
)

// Resolve picks the shell for a new Windows session.
//
// Precedence: explicit override, HSSH_SHELL, pwsh.exe, powershell.exe, then
// %COMSPEC% (cmd.exe). PowerShell is preferred because it renders UTF-8 and
// colour output more predictably than cmd.exe.
func Resolve(override string) (Spec, error) {
	if override != "" {
		if p, ok := resolveWindowsPath(override); ok {
			return specFor(p), nil
		}
		return Spec{}, ErrNotFound
	}
	if s := os.Getenv("HSSH_SHELL"); s != "" {
		if p, ok := resolveWindowsPath(s); ok {
			return specFor(p), nil
		}
	}
	for _, c := range []string{
		"pwsh.exe",
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe"),
		"powershell.exe",
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
	} {
		if c == "" {
			continue
		}
		if p, ok := resolveWindowsPath(c); ok {
			return specFor(p), nil
		}
	}
	if cs := os.Getenv("COMSPEC"); cs != "" {
		if p, ok := resolveWindowsPath(cs); ok {
			return specFor(p), nil
		}
	}
	return Spec{}, ErrNotFound
}

// specFor decides how to launch a Windows shell so it behaves interactively.
func specFor(path string) Spec {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "powershell") || base == "pwsh.exe":
		// -NoLogo skips the banner; a login-style profile gives the user their
		// prompt. Reading commands from stdin (which is the ConPTY) is implicit.
		return Spec{
			Path:  path,
			Args:  []string{"-NoLogo", "-NoExit"},
			Label: base,
		}
	case base == "cmd.exe":
		return Spec{Path: path, Label: base}
	case base == "nu.exe" || base == "nu":
		return Spec{Path: path, Label: base}
	default:
		return Spec{Path: path, Label: base}
	}
}

func resolveWindowsPath(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if strings.ContainsAny(name, `:\/`) {
		if st, err := os.Stat(name); err == nil && !st.IsDir() {
			return name, true
		}
		return "", false
	}
	if p, err := lookPath(name); err == nil {
		return p, true
	}
	return "", false
}
