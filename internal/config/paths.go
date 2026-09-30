package config

import (
	"os"
	"path/filepath"
)

// HSSHDir returns the single home for everything HSSH stores on disk:
//
//	~/.hssh/
//	  host.json        optional host config (fallback)
//	  config.json      alternate name for the same file
//	  sessions/<id>/   per-session working directories (--per-session-cwd)
//	  history/<id>     per-session shell history (HISTFILE)
//	  logs/            reserved for future file logs (currently unused)
//
// HSSH_DIR overrides the location (used by tests to avoid touching the real
// home). Nothing is ever created directly under $HOME or /tmp anymore.
func HSSHDir() string {
	if v := os.Getenv("HSSH_DIR"); v != "" {
		return v
	}
	return filepath.Join(homeDir(), ".hssh")
}

// SessionsRoot is ~/.hssh/sessions.
func SessionsRoot() string { return filepath.Join(HSSHDir(), "sessions") }

// HistoryDir is ~/.hssh/history.
func HistoryDir() string { return filepath.Join(HSSHDir(), "history") }

// HistoryFile returns the per-session shell history file. Each session gets
// its own file so concurrent shells never interleave or truncate each
// other's history.
func HistoryFile(sessionID string) string {
	if sessionID == "" {
		sessionID = "shared"
	}
	return filepath.Join(HistoryDir(), sessionID)
}

// EnsureHSSHDir creates ~/.hssh, sessions/ and history/ with 0700. It is
// idempotent and safe for concurrent callers; MkdirAll with an existing dir
// is a no-op.
func EnsureHSSHDir() (string, error) {
	base := HSSHDir()
	for _, d := range []string{base, SessionsRoot(), HistoryDir(), filepath.Join(base, "logs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}
	return base, nil
}

// ConfigCandidates returns the JSON config files checked in order, after
// HSSH_CONFIG and ./hssh.json. The first existing file wins.
func ConfigCandidates() []string {
	return []string{
		filepath.Join(HSSHDir(), "host.json"),
		filepath.Join(HSSHDir(), "config.json"),
		filepath.Join(homeDir(), ".config", "hssh", "host.json"),
	}
}
