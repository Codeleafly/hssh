package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "DEBUG": LevelDebug, "verbose": LevelDebug,
		"info": LevelInfo, "": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn,
		"error": LevelError, "fatal": LevelError,
		"off": LevelOff, "none": LevelOff, "silent": LevelOff,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseLevel("shouty"); err == nil {
		t.Fatal("an unknown level should be reported")
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelWarn, false)
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	out := buf.String()
	if strings.Contains(out, "d") || strings.Contains(out, " i ") {
		t.Fatalf("records below the level were written:\n%s", out)
	}
	if !strings.Contains(out, "w") || !strings.Contains(out, "e") {
		t.Fatalf("records at or above the level were dropped:\n%s", out)
	}
}

func TestOffSilencesEverything(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelOff, false)
	l.Error("boom")
	if buf.Len() != 0 {
		t.Fatalf("LevelOff wrote output: %q", buf.String())
	}
}

func TestSecretFieldsAreRedacted(t *testing.T) {
	// The whole point of the logger's key filter: a careless call site cannot
	// leak a credential.
	var buf bytes.Buffer
	l := New(&buf, LevelInfo, false)
	secrets := map[string]string{
		"password":     "pw-value-1",
		"token":        "tok-value-2",
		"secret":       "sec-value-3",
		"api_key":      "akey-value-4",
		"apiKey":       "akey-value-5",
		"private_key":  "pkey-value-6",
		"credential":   "cred-value-7",
		"passwordHash": "phash-value-8",
		"auth_value":   "aval-value-9",
		"cookie":       "cookie-value-10",
	}
	fields := make([]Field, 0, len(secrets))
	for k, v := range secrets {
		fields = append(fields, F(k, v))
	}
	l.Info("auth", fields...)
	l.Info("auth", F("session", "abc"))

	out := buf.String()
	for k, v := range secrets {
		if strings.Contains(out, v) {
			t.Fatalf("secret for field %q leaked into the log:\n%s", k, out)
		}
		if !strings.Contains(out, k+"="+Redacted) {
			t.Fatalf("field %q was not redacted:\n%s", k, out)
		}
	}
	// Non-secret fields must survive.
	if !strings.Contains(out, "abc") {
		t.Fatalf("a harmless field was dropped:\n%s", out)
	}
}

func TestSecretsInsideMessageValuesAreScrubbed(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo, false)
	// Even when the value is not obviously labelled as a secret, a
	// "password=..." pattern in free text is scrubbed.
	l.Info("handshake", F("detail", "connecting with password=hunter2 to host"))
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Fatalf("a password embedded in a message value leaked:\n%s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Fatalf("expected a redaction marker:\n%s", out)
	}
}

func TestWithInheritsAndDeduplicates(t *testing.T) {
	var buf bytes.Buffer
	base := New(&buf, LevelInfo, false).With(F("session", "a91f"))
	child := base.With(F("client", "10.0.0.1"))

	child.Info("pty created", F("session", "a91f"), F("shell", "bash"))
	out := buf.String()
	if n := strings.Count(out, "session="); n != 1 {
		t.Fatalf("session field appears %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "client=10.0.0.1") || !strings.Contains(out, "shell=bash") {
		t.Fatalf("fields were lost:\n%s", out)
	}

	// The parent must not inherit the child's fields.
	buf.Reset()
	base.Info("another", F("session", "a91f"))
	if strings.Contains(buf.String(), "client=") {
		t.Fatalf("a child leaked its fields into the parent:\n%s", buf.String())
	}
}

func TestWithOverrideWins(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo, false).With(F("session", "parent"))
	l.Info("evt", F("session", "child"))
	if strings.Count(buf.String(), "session=") != 1 {
		t.Fatalf("expected exactly one session field:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "session=child") {
		t.Fatalf("the more specific value should win:\n%s", buf.String())
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo, true)
	l.Warn("client disconnected", F("session", "a91f"), F("password", "nope"))
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if rec["event"] != "client disconnected" {
		t.Fatalf("unexpected event: %v", rec["event"])
	}
	if rec["session"] != "a91f" {
		t.Fatalf("session missing: %v", rec)
	}
	if rec["password"] != Redacted {
		t.Fatalf("password not redacted in JSON: %v", rec)
	}
}

func TestSetLevelAppliesToChildren(t *testing.T) {
	var buf bytes.Buffer
	base := New(&buf, LevelError, false)
	child := base.With(F("session", "x"))
	buf.Reset()
	child.Info("should be hidden")
	if buf.Len() != 0 {
		t.Fatalf("child ignored the parent level: %q", buf.String())
	}
	base.SetLevel(LevelInfo)
	child.Info("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Fatalf("SetLevel did not reach the child: %q", buf.String())
	}
}

func TestEnabled(t *testing.T) {
	l := New(&bytes.Buffer{}, LevelWarn, false)
	if l.Enabled(LevelInfo) {
		t.Fatal("info should be disabled at warn level")
	}
	if !l.Enabled(LevelError) {
		t.Fatal("error should be enabled at warn level")
	}
}

func TestDiscardWritesNothing(t *testing.T) {
	l := Discard()
	l.Error("nothing")
	if l.Enabled(LevelError) {
		t.Fatal("Discard must not report anything as enabled")
	}
}

func TestLevelString(t *testing.T) {
	want := map[Level]string{
		LevelDebug: "DEBUG", LevelInfo: "INFO ",
		LevelWarn: "WARN ", LevelError: "ERROR", LevelOff: "OFF  ",
	}
	for lv, s := range want {
		if lv.String() != s {
			t.Fatalf("Level(%d).String() = %q, want %q", lv, lv.String(), s)
		}
	}
}
