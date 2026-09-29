package shell

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolvePrefersAnExplicitOverride(t *testing.T) {
	p := pickShellPath(t)
	spec, err := Resolve(p)
	if err != nil {
		t.Fatalf("resolve %q: %v", p, err)
	}
	if spec.Path == "" {
		t.Fatal("no shell path resolved")
	}
	if len(spec.Args) > 0 && spec.Args[0] != "-l" {
		t.Fatalf("an interactive shell should be started as a login shell, got args %v", spec.Args)
	}
}

func TestResolveRejectsAMissingOverride(t *testing.T) {
	if _, err := Resolve(filepath.Join(t.TempDir(), "not-a-shell")); err == nil {
		t.Fatal("a shell that does not exist must be reported, not silently replaced")
	}
}

func TestResolveFallsBackWhenNoOverride(t *testing.T) {
	spec, err := Resolve("")
	if err != nil {
		t.Skipf("this machine has no discoverable shell: %v", err)
	}
	st, err := os.Stat(spec.Path)
	if err != nil {
		t.Fatalf("resolved shell does not exist: %s: %v", spec.Path, err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("resolved shell is not executable: %s", spec.Path)
	}
	if spec.Label == "" {
		t.Fatal("the spec must carry a label for the session table")
	}
}

func TestResolveHonoursSHELLEnv(t *testing.T) {
	p := pickShellPath(t)
	t.Setenv("SHELL", p)
	spec, err := Resolve("")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if spec.Path != p {
		t.Fatalf("$SHELL (%s) was not used; got %s", p, spec.Path)
	}
}

func TestDefaultEnvIsFilteredAndOverridable(t *testing.T) {
	t.Setenv("HSSH_SHOULD_NOT_LEAK", "hunter2")
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/home/tester")

	env := DefaultEnv(map[string]string{
		"TERM":         "xterm-256color",
		"HSSH_SESSION": "abc123",
	})
	joined := strings.Join(env, "\n")

	if strings.Contains(joined, "hunter2") {
		t.Fatalf("DefaultEnv leaked a host variable that is not on the allowlist:\n%s", joined)
	}
	if !strings.Contains(joined, "TERM=xterm-256color") {
		t.Fatalf("the requested TERM is missing:\n%s", joined)
	}
	if !strings.Contains(joined, "HSSH_SESSION=abc123") {
		t.Fatalf("the requested HSSH_SESSION is missing:\n%s", joined)
	}
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") {
		t.Fatalf("PATH from the host environment should pass through:\n%s", joined)
	}
}

func TestDefaultEnvDoesNotDuplicateKeys(t *testing.T) {
	env := DefaultEnv(map[string]string{"TERM": "xterm-256color"})
	seen := map[string]int{}
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			t.Fatalf("malformed environment entry %q", kv)
		}
		seen[kv[:i]]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Fatalf("key %q appears %d times; the last definition wins but duplicates are sloppy", k, n)
		}
	}
}

func TestHomeDirIsUsable(t *testing.T) {
	h := HomeDir()
	if h == "" || h == "." {
		if runtime.GOOS == "windows" {
			t.Skip("no home directory on this machine")
		}
		t.Fatalf("HomeDir returned %q", h)
	}
}

func TestIsInteractiveShell(t *testing.T) {
	for _, s := range []string{"bash", "zsh", "fish", "sh", "dash"} {
		if !isInteractiveShell(s) {
			t.Fatalf("%s should be recognised as an interactive shell", s)
		}
	}
	for _, s := range []string{"vim", "less", "top", "htop"} {
		if isInteractiveShell(s) {
			t.Fatalf("%s is not a shell", s)
		}
	}
}

func TestEnvBool(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("HSSH_TEST_BOOL", v)
		if !envBool("HSSH_TEST_BOOL") {
			t.Fatalf("%q should be truthy", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "", "maybe"} {
		t.Setenv("HSSH_TEST_BOOL", v)
		if envBool("HSSH_TEST_BOOL") {
			t.Fatalf("%q should be falsy", v)
		}
	}
}

// pickShellPath finds an absolute path to a shell for the override test.
func pickShellPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, c := range []string{"powershell.exe", "cmd.exe"} {
			if p := lookPathOrEmpty(c); p != "" {
				return p
			}
		}
		t.Skip("no Windows shell available")
	}
	for _, c := range []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/data/data/com.termux/files/usr/bin/sh"} {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skip("no unix shell available")
	return ""
}

func lookPathOrEmpty(name string) string {
	p, err := lookPath(name)
	if err != nil {
		return ""
	}
	return p
}
