// Package logging provides HSSH's structured logger.
//
// The important property is redaction: field values whose key looks like a
// secret are replaced before the record is ever formatted, so a stray
// log.Info("auth", "password", pw) cannot leak a credential. The argument is
// paired with a regex scrubber for defence in depth.
package logging

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelOff
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO "
	case LevelWarn:
		return "WARN "
	case LevelError:
		return "ERROR"
	default:
		return "OFF  "
	}
}

// ParseLevel maps a name to a Level.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace", "verbose":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error", "fatal":
		return LevelError, nil
	case "off", "none", "silent":
		return LevelOff, nil
	}
	return LevelInfo, fmt.Errorf("logging: unknown level %q", s)
}

// secretKey matches field names that must never be printed.
var secretKey = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[-_]?key|credential|auth[-_]?value|private[-_]?key|cookie|session[-_]?token)`)

// secretValue scrubs anything that looks like a long credential embedded in a
// message.
var secretValue = regexp.MustCompile(`(?i)(password|token|secret|apikey|api_key)\s*[=:]\s*(\S+)`)

// Redacted is the placeholder written instead of a secret.
const Redacted = "[redacted]"

// Logger writes structured, single-line records.
//
// The zero value is not usable; call New. A Logger is a value, but it is meant
// to be shared by pointer or through With, which returns a child that carries
// extra fields and shares the same sink and level.
type Logger struct {
	mu     *sync.Mutex
	w      io.Writer
	level  *Level
	json   bool
	fields []Field
}

// Field is a key/value pair attached to a record.
type Field struct {
	Key   string
	Value any
}

// New builds a logger writing to w.
func New(w io.Writer, level Level, jsonFormat bool) *Logger {
	lv := level
	return &Logger{w: w, level: &lv, json: jsonFormat, mu: &sync.Mutex{}}
}

// Default builds the process-wide default logger (human readable, stderr).
func Default(level string) *Logger {
	l, err := ParseLevel(level)
	if err != nil {
		l = LevelInfo
	}
	return New(os.Stderr, l, os.Getenv("HSSH_LOG_FORMAT") == "json")
}

// With returns a logger that adds the given fields to every record. The child
// shares the sink, the level and the mutex, so concurrent writes from several
// sessions stay serialised and a SetLevel on either is seen by both.
func (l *Logger) With(fields ...Field) *Logger {
	return &Logger{
		mu:     l.mu,
		w:      l.w,
		level:  l.level,
		json:   l.json,
		fields: append(append([]Field{}, l.fields...), fields...),
	}
}

// F is a shorthand constructor for a field.
func F(key string, val any) Field { return Field{Key: key, Value: val} }

// SetLevel changes the verbosity.
func (l *Logger) SetLevel(lv Level) {
	l.mu.Lock()
	*l.level = lv
	l.mu.Unlock()
}

// Enabled reports whether records at lv are written.
func (l *Logger) Enabled(lv Level) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return lv >= *l.level && *l.level != LevelOff
}

func (l *Logger) log(lv Level, event string, fields []Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if *l.level == LevelOff || lv < *l.level {
		return
	}
	all := mergeFields(l.fields, fields)
	for i := range all {
		if secretKey.MatchString(all[i].Key) {
			all[i].Value = Redacted
		} else if s, ok := all[i].Value.(string); ok {
			all[i].Value = secretValue.ReplaceAllString(s, "$1="+Redacted)
		}
	}

	if l.json {
		writeJSON(l.w, lv, event, all)
		return
	}
	var sb strings.Builder
	sb.WriteString(time.Now().Format("15:04:05.000"))
	sb.WriteByte(' ')
	sb.WriteString(lv.String())
	sb.WriteByte(' ')
	sb.WriteString(pad(event, 22))
	for _, f := range all {
		sb.WriteByte(' ')
		sb.WriteString(f.Key)
		sb.WriteByte('=')
		sb.WriteString(fmt.Sprint(f.Value))
	}
	sb.WriteByte('\n')
	_, _ = io.WriteString(l.w, sb.String())
}

// mergeFields concatenates the inherited and per-record fields, dropping any
// key that was already set on the parent logger. A child that carries
// session=abc must not print session=abc twice when the caller also passes it.
func mergeFields(inherited, extra []Field) []Field {
	seen := make(map[string]bool, len(inherited))
	for _, f := range inherited {
		seen[f.Key] = true
	}
	out := make([]Field, 0, len(inherited)+len(extra))
	out = append(out, inherited...)
	for _, f := range extra {
		if seen[f.Key] {
			// Replace in place so the most specific value wins.
			for i := range out {
				if out[i].Key == f.Key {
					out[i] = f
					break
				}
			}
			continue
		}
		seen[f.Key] = true
		out = append(out, f)
	}
	return out
}

func writeJSON(w io.Writer, lv Level, event string, fields []Field) {
	var sb strings.Builder
	sb.WriteString(`{"ts":`)
	fmt.Fprintf(&sb, "%q", time.Now().Format(time.RFC3339Nano))
	fmt.Fprintf(&sb, `,"level":%q,"event":%q`, lv.String(), event)
	for _, f := range fields {
		fmt.Fprintf(&sb, ",%q:%q", f.Key, fmt.Sprint(f.Value))
	}
	sb.WriteString("}\n")
	_, _ = io.WriteString(w, sb.String())
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// Debug logs at debug level.
func (l *Logger) Debug(event string, fields ...Field) { l.log(LevelDebug, event, fields) }

// Info logs at info level.
func (l *Logger) Info(event string, fields ...Field) { l.log(LevelInfo, event, fields) }

// Warn logs at warn level.
func (l *Logger) Warn(event string, fields ...Field) { l.log(LevelWarn, event, fields) }

// Error logs at error level.
func (l *Logger) Error(event string, fields ...Field) { l.log(LevelError, event, fields) }

// Discard returns a logger that writes nothing, for tests and --quiet.
func Discard() *Logger { return New(io.Discard, LevelOff, false) }
