// Package cli implements the hssh command line: flag parsing, the interactive
// confirmation prompts, and the polished output for each command.
package cli

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Flags is a parsed `--key=value` / `--key value` / `--flag` set.
//
// It supports both syntaxes the specification asks for:
//
//	hssh host --port=8080
//	hssh connect=http://server:8080
//	hssh connect http://server:8080
//	hssh connect --url http://server:8080
type Flags struct {
	values map[string]string
	bools  map[string]bool
	args   []string
}

// NewFlags builds an empty flag set.
func NewFlags() *Flags {
	return &Flags{values: map[string]string{}, bools: map[string]bool{}}
}

// ErrHelp is returned when --help or -h is present.
var ErrHelp = errors.New("help requested")

// ErrUnknownFlag is returned for an unrecognised flag.
type ErrUnknownFlag struct{ Name string }

func (e *ErrUnknownFlag) Error() string { return "unknown flag --" + e.Name }

// FlagSpec declares the flags a command accepts.
//
// Both halves matter. An unknown flag must be an error, not something silently
// ignored: a mistyped --prot=8080 would otherwise leave the host listening on
// the default port, and a mistyped --allow-unauthenticated would silently skip
// the security prompt.
type FlagSpec struct {
	// Values are flags that take an argument.
	Values []string
	// Bools are flags that take no argument.
	Bools []string
}

// Merge combines specs.
func (s FlagSpec) Merge(others ...FlagSpec) FlagSpec {
	out := s
	for _, o := range others {
		out.Values = append(append([]string{}, out.Values...), o.Values...)
		out.Bools = append(append([]string{}, out.Bools...), o.Bools...)
	}
	return out
}

// hostFlags is the set `hssh host` accepts.
var hostFlags = FlagSpec{
	Values: []string{
		"host", "port", "shell", "workdir", "password", "token",
		"tls-cert", "tls-key", "max-sessions", "idle-timeout",
		"session-timeout", "heartbeat", "output-buffer", "log-level",
	},
	Bools: []string{"allow-unauthenticated", "allow-resume", "per-session-cwd", "quiet", "no-color", "generate-token"},
}

// connectFlags is the set `hssh connect` and `hssh sessions` accept.
var connectFlags = FlagSpec{
	Values: []string{
		"url", "server", "password", "token", "ca", "disconnect-key",
		"timeout", "log-level", "term",
	},
	Bools: []string{"insecure", "quiet", "no-color", "no-status"},
}

// sessionFlags adds the reattach flag.
var sessionFlags = connectFlags.Merge(FlagSpec{Values: []string{"session"}})

// Parse consumes argv according to spec. Both syntaxes are supported:
//
//	--port=8080
//	--port 8080
//
// and a value flag may be spelled -p for its short form.
func Parse(argv []string, spec FlagSpec) (*Flags, error) {
	known := make(map[string]bool, len(spec.Values))
	for _, v := range spec.Values {
		known[v] = true
	}
	isBool := make(map[string]bool, len(spec.Bools))
	for _, b := range spec.Bools {
		isBool[b] = true
	}
	f := NewFlags()
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			f.args = append(f.args, argv[i+1:]...)
			return f, nil
		case a == "-h":
			return f, ErrHelp
		case a == "--help":
			return f, ErrHelp
		case a == "--version" || a == "-v":
			return f, ErrVersion
		case strings.HasPrefix(a, "--"):
			body := a[2:]
			name, value, hasValue := strings.Cut(body, "=")
			if name == "help" || name == "version" {
				if name == "help" {
					return f, ErrHelp
				}
				return f, ErrVersion
			}
			if !isBool[name] && !known[name] {
				return f, &ErrUnknownFlag{Name: name}
			}
			if isBool[name] {
				if !hasValue {
					value = "true"
				}
				f.bools[name] = truthy(value)
				continue
			}
			if !hasValue {
				// `--port 8080`
				if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
					i++
					value = argv[i]
					hasValue = true
				}
			}
			if !hasValue {
				return f, fmt.Errorf("flag --%s needs a value", name)
			}
			f.values[name] = value
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short forms.
			short := a[1:]
			name, ok := shortNames[short]
			if !ok {
				return f, fmt.Errorf("unknown flag -%s", short)
			}
			if !isBool[name] && !known[name] {
				return f, &ErrUnknownFlag{Name: name}
			}
			if isBool[name] {
				f.bools[name] = true
				continue
			}
			if i+1 < len(argv) {
				i++
				f.values[name] = argv[i]
				continue
			}
			return f, fmt.Errorf("flag -%s needs a value", short)
		default:
			f.args = append(f.args, a)
		}
	}
	return f, nil
}

// ErrVersion is returned for --version.
var ErrVersion = errors.New("version requested")

var shortNames = map[string]string{
	"p": "port",
	"s": "shell",
	"q": "quiet",
	"k": "password",
	"t": "token",
	"c": "ca",
	"n": "insecure",
	"w": "workdir",
}

// String returns a flag value, or def when absent.
func (f *Flags) String(name, def string) string {
	if v, ok := f.values[name]; ok {
		return v
	}
	return def
}

// Int returns an integer flag.
func (f *Flags) Int(name string, def int) (int, error) {
	v, ok := f.values[name]
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("--%s must be a number, got %q", name, v)
	}
	return n, nil
}

// Duration returns a duration flag, accepting bare seconds.
func (f *Flags) Duration(name string, def time.Duration) (time.Duration, error) {
	v, ok := f.values[name]
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err == nil {
		return d, nil
	}
	n, cerr := strconv.Atoi(v)
	if cerr != nil {
		return def, fmt.Errorf("--%s must be a duration like 30s or 5m, got %q", name, v)
	}
	return time.Duration(n) * time.Second, nil
}

// Bool returns a boolean flag.
func (f *Flags) Bool(name string) bool { return f.bools[name] }

// Has reports whether a flag was given.
func (f *Flags) Has(name string) bool {
	if f.bools[name] {
		return true
	}
	_, ok := f.values[name]
	return ok
}

// Args returns the positional arguments.
func (f *Flags) Args() []string { return f.args }

// Arg returns the nth positional argument or "".
func (f *Flags) Arg(n int) string {
	if n < len(f.args) {
		return f.args[n]
	}
	return ""
}

// Keys returns the flag names that were set, sorted, for diagnostics.
func (f *Flags) Keys() []string {
	seen := map[string]bool{}
	for k := range f.values {
		seen[k] = true
	}
	for k := range f.bools {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on", "y":
		return true
	}
	return false
}
