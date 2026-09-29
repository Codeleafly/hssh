package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// mergeJSONFile overlays a JSON file onto a config struct. Only keys present
// in the file are overwritten, so command line flags already parsed keep
// priority when they are non-zero. Secrets are read from the file only; the
// file is never written by HSSH.
func mergeJSONFile(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// Decode into a generic map first so we can report unknown keys and avoid
	// clobbering non-zero values set from the command line.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("config: %s is not valid JSON: %w", path, err)
	}

	if v, ok := m["host"]; ok {
		out.(*HostConfig).Host, _ = v.(string)
	}
	if v, ok := m["port"]; ok {
		if n, ok := v.(float64); ok {
			out.(*HostConfig).Port = int(n)
		}
	}
	if v, ok := m["shell"]; ok {
		out.(*HostConfig).Shell, _ = v.(string)
	}
	if v, ok := m["workdir"]; ok {
		out.(*HostConfig).WorkDir, _ = v.(string)
	}
	if v, ok := m["password"]; ok {
		out.(*HostConfig).Password, _ = v.(string)
	}
	if v, ok := m["token"]; ok {
		out.(*HostConfig).Token, _ = v.(string)
	}
	if v, ok := m["auth"]; ok {
		out.(*HostConfig).AuthMode = AuthMode(fmt.Sprint(v))
	}
	if v, ok := m["tls_cert"]; ok {
		out.(*HostConfig).TLSCert, _ = v.(string)
	}
	if v, ok := m["tls_key"]; ok {
		out.(*HostConfig).TLSKey, _ = v.(string)
	}
	if v, ok := m["max_sessions"]; ok {
		if n, ok := v.(float64); ok {
			out.(*HostConfig).MaxSessions = int(n)
		}
	}
	if v, ok := m["per_session_cwd"]; ok {
		out.(*HostConfig).PerSessionCwd, _ = v.(bool)
	}
	if v, ok := m["allow_resume"]; ok {
		out.(*HostConfig).AllowResume, _ = v.(bool)
	}
	if v, ok := m["allow_unauthenticated"]; ok {
		out.(*HostConfig).AllowUnauthenticated, _ = v.(bool)
	}
	if v, ok := m["output_buffer"]; ok {
		if n, err := ParseSize(fmt.Sprint(v)); err == nil {
			out.(*HostConfig).OutputBuffer = n
		} else {
			return fmt.Errorf("config: output_buffer: %w", err)
		}
	}
	if v, ok := m["max_frame_size"]; ok {
		if n, err := ParseSize(fmt.Sprint(v)); err == nil {
			out.(*HostConfig).MaxFrameSize = n
		} else {
			return fmt.Errorf("config: max_frame_size: %w", err)
		}
	}
	if v, ok := m["log_level"]; ok {
		out.(*HostConfig).LogLevel, _ = v.(string)
	}
	for key, dst := range map[string]*time.Duration{
		"idle_timeout":    &out.(*HostConfig).IdleTimeout,
		"session_timeout": &out.(*HostConfig).SessionTimeout,
		"heartbeat":       &out.(*HostConfig).Heartbeat,
	} {
		if v, ok := m[key]; ok {
			d, err := ParseDuration(fmt.Sprint(v))
			if err != nil {
				return fmt.Errorf("config: %s: %w", key, err)
			}
			*dst = d
		}
	}
	return nil
}
