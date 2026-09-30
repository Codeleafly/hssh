# HSSH — a real remote terminal over HTTP/WebSocket

> **Topic:** `go` `ssh-alternative` `websocket` `pty` `remote-shell` `terminal` `devops` `termux` — SSH-like PTY sessions without the SSH protocol.

HSSH is an SSH-like remote terminal written in Go. The transport is not the
SSH protocol: the client and host talk **HTTP handshake + WebSocket**, and the
host runs a **real shell inside a real PTY** (native POSIX PTY, ConPTY on
Windows). The client never emulates a terminal — it puts the local tty into
raw mode and passes bytes through, so `vim`, `top`, colours and UTF-8 work
exactly as they would over SSH.

```text
┌──────────┐   HTTP GET /health (discovery)    ┌──────────┐
│  hssh    │ ────────────────────────────────▶ │  hssh    │
│ connect  │   WebSocket /connect (hssh.v1)    │  host    │
│ (client) │ ◀════════════════════════════════ │ (server) │
└──────────┘   binary frames = PTY bytes       └──────────┘
               text frames   = JSON control         │ PTY
                                                    ▼ real shell
```

## Features

- Real PTY + real shell (`bash`/`zsh`/`sh` auto-detected, override with `--shell` or `HSSH_SHELL`). No pipe fallback — unsupported platforms get an error.
- Password or token auth, TLS (`https`/`wss`), plaintext credential refusal on both ends (client never sends secrets over `ws://`, nor to an `AuthNone` host).
- Session table (`hssh sessions`), per-session working-directory isolation under `~/.hssh/sessions`, per-session history under `~/.hssh/history`, idle/session timeouts, heartbeat keepalive.
- Idle sessions are never killed as “slow”: slow-client detection requires a backed-up output queue.
- Session resume: `hssh host --allow-resume` + `hssh connect --session=<id>`.
- Strict flags: unknown flags are errors, never silently ignored. Flags win over `HSSH_*` env over JSON file.
- Structured logs with secret redaction.

## Install

Requires Go `1.27.1+` (`go.mod`).

```bash
git clone https://github.com/Codeleafly/hssh.git hssh
cd hssh
go build -o bin/hssh ./cmd/hssh
```

Or download a versioned binary from
[Releases](https://github.com/Codeleafly/hssh/releases) (see below).

Windows cross-compile:

```bash
GOOS=windows go build ./...
```

## Quickstart (localhost lab)

Terminal 1 — start the host:

```bash
./bin/hssh host --port 8080 --allow-unauthenticated
```

Terminal 2 — connect:

```bash
./bin/hssh connect=http://127.0.0.1:8080
```

Inside the session `Ctrl+C`/`Ctrl+D` go to the **remote** shell.
Disconnect cleanly with `Ctrl+]` or `~.` typed at the start of a line.
Window resizes are forwarded automatically.

## Usage

### `hssh host` — serve shells

```bash
./bin/hssh host --port 8080 --allow-unauthenticated
./bin/hssh host --port 8443 --tls-cert server.crt --tls-key server.key --password 's3cret'
./bin/hssh host --port 8443 --tls-cert server.crt --tls-key server.key --token "$(./bin/hssh token)"
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `0.0.0.0` | Bind address |
| `--port` / `-p` | `8080` | Listen port |
| `--shell` / `-s` | auto | Shell to run: `HSSH_SHELL` → `$SHELL` → `bash/zsh/fish/ash/dash/sh` (Windows: `pwsh/powershell/%COMSPEC%`) |
| `--workdir` / `-w` | home | Initial working directory |
| `--password` / `-k` | — | Require a password (client must use `https`/`wss`) |
| `--token` / `-t` | — | Require a token |
| `--tls-cert` / `--tls-key` | — | Serve HTTPS/WSS (must be given together) |
| `--allow-unauthenticated` | false | Skip the no-auth confirmation prompt |
| `--allow-resume` | false | Let clients reattach with `--session=<id>` |
| `--per-session-cwd` | false | Private working directory per session |
| `--max-sessions` | `0` (= unlimited) | Reject new sessions above this count |
| `--idle-timeout` | off | e.g. `30m`, `90s`, or bare seconds (`90`) — close sessions with no input |
| `--session-timeout` | off | Absolute max session lifetime from creation (e.g. `2h`) |
| `--heartbeat` | `30s` | Keepalive interval |
| `--output-buffer` | `4M` | Per-session output queue ceiling (`512K`, `2M`, `4MiB`, `1G`) |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`, `off` (host default `info`, client default `warn`) |
| `--quiet` / `-q` | false | Silence logs (`--log-level=off`) |
| `--no-color` | false | Disable colour output (also `NO_COLOR`, `HSSH_ASCII=1` for ASCII) |
| `--generate-token` | — | Print a strong token and exit (same as `hssh token`, ignores other flags) |

Running without auth prints a warning and asks for confirmation unless
`--allow-unauthenticated` is given. Precedence is flags > `HSSH_PASSWORD` /
`HSSH_TOKEN` env > JSON file > defaults, and the confirmation runs after the
file merge so a file cannot silently downgrade auth. `hssh serve` is an alias
for `hssh host`.

### `hssh connect` — open a remote shell

```bash
./bin/hssh connect http://127.0.0.1:8080
./bin/hssh connect=https://example.com:8443 --password 's3cret'
HSSH_PASSWORD='s3cret' ./bin/hssh connect https://example.com:8443
./bin/hssh connect https://example.com:8443 --session <id>   # resume
```

| Flag | Meaning |
|---|---|
| `--password` / `-k`, `--token` / `-t` | Credential (only sent over `https`/`wss`; never sent to an `AuthNone` host) |
| `--ca` / `-c` | PEM bundle to verify the server certificate (bad file is an error) |
| `--insecure` / `-n` | Skip verification (lab only) |
| `--disconnect-key` | Custom escape sequence (`0x1d`, `C-]`, `~.`, `1b 5b`); defaults `Ctrl+]` and `~.` at line start |
| `--session` | Reattach to a live session (host needs `--allow-resume`; `connect` only, not `sessions`) |
| `--cwd` | Start in this **server** directory (default: host working dir; `connect` only) |
| `--timeout` | Connection timeout (default `15s`; bare seconds accepted, e.g. `10`) |
| `--term` | Override `TERM` sent to the server (default: `$TERM` or `xterm-256color`) |
| `--url` / `--server` | Alternate spellings for the target URL |
| `--no-status` | Skip the connection banner |
| `--log-level` (default `warn`), `--quiet` / `-q`, `--no-color` | Client log verbosity |

Target forms are all first-class: `hssh connect http://host:8080`,
`hssh connect=http://host:8080`, `hssh connect --url http://host:8080`.

A password is never taken from the URL. `HSSH_PASSWORD` / `HSSH_TOKEN`
avoid putting secrets in shell history. `hssh help`, `hssh connect --help`,
`hssh host --help`, and `--version` / `-v` are available.

### Working directory — exact-terminal rules

Like SSH and VS Code's terminal, every session starts in a real directory
and the server always knows it:

- **Default is home.** With no `--workdir` and no `--cwd`, the shell starts
  in the server user's home directory, with a matching `$PWD`.
- **Host selects with `--workdir`.** `./bin/hssh host --workdir /srv/app`
  makes that the default for every session.
- **Client requests with `--cwd`.** `./bin/hssh connect=URL --cwd /srv/app`
  starts there. The path is on the **server** (relative paths resolve
  against the host working directory). A missing directory or a `--cwd`
  against a `--per-session-cwd` host fails fast with an error — never a
  silent landing somewhere unexpected.
- **`hssh sessions` shows a CWD column** with each session's directory.
- **Live tracking.** Shells with shell-integration enabled (VS Code style)
  report every `cd` via OSC 7 and the table follows in real time. Enable it:

```bash
# bash (~/.bashrc)
PROMPT_COMMAND='printf "\e]7;file://localhost%s\e\\" "$PWD";'"$PROMPT_COMMAND"

# zsh (~/.zshrc)
precmd() { printf '\e]7;file://localhost%s\e\\' "$PWD"; }

# fish (~/.config/fish/config.fish)
function __hssh_osc7 --on-variable PWD
  printf '\e]7;file://localhost%s\e\\' "$PWD"
end
```

Shells without integration keep showing the creation-time directory.

### `hssh sessions` — list live sessions

```bash
./bin/hssh sessions http://127.0.0.1:8080
./bin/hssh sessions --url http://127.0.0.1:8080 --password 's3cret'
```

Accepts the full `connect` auth/TLS flags (`--password/--token/--ca/--insecure`,
`--url/--server`, `--timeout`, `--log-level/--quiet/--no-color`) but not
`--session`/`--cwd`. With no URL it defaults to `http://localhost:8080`.

Shows id, client, shell, working directory, size, age, idle time and
traffic. Never shows credentials or terminal content.

### `hssh token` / `hssh version`

```bash
./bin/hssh token     # strong random token for --token
./bin/hssh version   # version, protocol, Go, PTY backend
```

### Environment variables

| Variable | Meaning |
|---|---|
| `HSSH_PASSWORD` / `HSSH_TOKEN` | Credential for host or client (flag wins over env over file) |
| `HSSH_SHELL` | Override shell auto-detection |
| `HSSH_CONFIG` | Path to a JSON host config file (else `./hssh.json`, else `~/.hssh/host.json`, else `~/.hssh/config.json`, else `~/.config/hssh/host.json`) |
| `HSSH_DIR` | Override the single HSSH home (default `~/.hssh`; test-only) |
| `HSSH_LOG_FORMAT=json` | Structured logs (`json` vs text) |
| `NO_COLOR` / `--no-color` | Disable colour output |
| `HSSH_ASCII=1` | Force ASCII glyphs (no box-drawing/Unicode) |
| `TERM` (`--term` overrides) | Terminal type sent as `terminal_start.term` (validated to `[A-Za-z0-9-_.]`, max 64) |
| `COLORFGBG` | Dark/light hint sent as `color_scheme` |
| `SHELL`, `HOME` (`USERPROFILE` on Windows) | Shell/home fallback for `--shell`/`--workdir` |
| `HSSH_SESSION`, `HSSH_CLIENT` | Set by the server inside each remote shell (id, colour-scheme hint) |

JSON keys: `host`, `port`, `shell`, `workdir`, `password`, `token`, `auth`,
`tls_cert`, `tls_key`, `max_sessions`, `per_session_cwd`, `allow_resume`,
`allow_unauthenticated`, `output_buffer` (`4M`), `max_frame_size`,
`log_level`, `idle_timeout`, `session_timeout`, `heartbeat` (durations like
`30s`/`5m` or bare seconds). Unknown keys are an error. `HSSH_TEST_BINARY`
is test-only.

### Disk layout — single `~/.hssh` home

HSSH never scatters files across `$HOME` or `/tmp`. Everything it stores
lives under one directory (`$HSSH_DIR` overrides it in tests):

```text
~/.hssh/
  host.json        optional config (also config.json; see HSSH_CONFIG above)
  sessions/<id>/   per-session working dirs (--per-session-cwd only)
  history/<id>     per-session shell history (HISTFILE, 0600)
  logs/            reserved (logs currently go to stderr)
```

In particular:

- `~/go` is the Go toolchain's `GOPATH` module cache, not HSSH.
- `~/hssh` is your project checkout itself, not created by the binary.
- `~/hsshbin`, `~/hsshrun` were your manual test dirs (binaries + logs),
  never created by HSSH code.
- Without `--per-session-cwd` HSSH creates no session dirs at all; with it
  the root is `~/.hssh/sessions`, never `/tmp/hssh-sessions-*`.
- Each remote shell gets `HISTFILE=~/.hssh/history/<session-id>` so
  concurrent sessions never share `~/.bash_history`.

## Security model

- Credentials travel only over TLS. Both client and server refuse
  password/token over plain `http`/`ws`.
- No-auth mode requires explicit confirmation (`--allow-unauthenticated`).
- A session id alone grants nothing: resume additionally requires the same
  client address **and** a fresh successful authentication, plus the host
  opt-in `--allow-resume`.
- Logs redact secrets by key name and by `password=/token=` value patterns.
- HTTP surface sends no CORS headers and validates `Origin` against `Host`
  (DNS-rebinding hardening). There is no browser client in v1 by design.

## Protocol (HSSH/1, summary)

- Discovery: `GET /health` (alias `GET /version`) →
  `{name, version, protocol, websocket, tls, auth, uptime_seconds, endpoints}`;
  `GET /` is a human index with `usage`. Endpoints are `/health` and `/connect`,
  subprotocol `hssh.v1` (`internal/wsx`).
- Terminal: `GET /connect` upgraded to WebSocket, subprotocol `hssh.v1`
  (mismatched subprotocol is rejected). No CORS headers are sent.
- Every WebSocket frame is `[1 byte opcode][payload]`.
  Opcodes: `0x01 input (c→s)`, `0x02 output (s→c)`, `0x10-0x1A` control,
  `0x20-0x21` ping/pong, `0x30-0x31` sessions. Control frames are capped at
  `1 MiB` (`MaxControlFrame`).
  Binary frames carry raw terminal bytes (no JSON/base64);
  text frames carry JSON control messages
  (`hello`, `auth`, `auth_result`, `terminal_start`, `terminal_input`,
  `input` payload, `output` payload, `resize`, `signal`
  (`INT|TERM|HUP|QUIT|KILL|WINCH|TSTP|CONT`), `exit`, `session_info`,
  `disconnect`, `error` (`protocol_mismatch/auth_failed/session_limit/
  pty_failed/shell_failed/resize_failed/internal_error/bad_message`),
  `ping`/`pong` (`seq`, `ts`), `sessions_request`, `sessions_list`).
- Handshake order per connection: `hello` → `auth_result` (challenge) →
  `auth` (with optional `resume` session id) → `auth_result` (ok) →
  `terminal_start` (`cols`, `rows`, `term`, `cwd`, `color_scheme`) or
  `sessions_request`. The handshake has a `20s` deadline covering
  `terminal_start`.

## Project layout

```text
cmd/hssh/main.go   entrypoint
internal/
  protocol/        opcodes, codec, message types (protocol.go, messages.go)
  pty/             real PTY: pty.go/handle.go, pty_unix.go/pty_windows.go/pty_unsupported.go, signal_*.go
  shell/           shell resolution + filtered environment (shell.go/shell_unix.go/shell_windows.go, allowlist)
  terminal/        server PTY session + pumps (session.go), escape parser (escape.go), OSC 7 live CWD (osc7.go), raw mode (terminal.go)
  auth/            password/token verifier, stateless, constant-time (auth.go)
  config/          flags + JSON file + validation (config.go/file.go)
  wsx/             hardened WebSocket wrapper: limits/origin/TLS/subprotocol (wsx.go/url.go: /connect, /health)
  httpapi/         /health (+/version alias), /, /connect
  server/          host, handshake, session lifecycle, resume (host.go/session.go/resume.go/sink.go)
  client/          dial, auth, raw-mode loops, sessions query (client.go/http.go: /health discovery, TERM/COLORFGBG)
  cli/             commands, flag parser, prompts, output (app.go/flags.go/prompt.go/support.go; `serve` alias)
  ui/              terminal printer (ui.go; NO_COLOR/HSSH_ASCII aware)
  sessions/        session registry (manager.go)
  logging/         redacting structured logger
tests/             e2e: real binaries driven through a real PTY (e2e_test.go/harness_test.go/helpers_test.go)
```

`hssh version` prints version, protocol, WebSocket subprotocol, Go, and the PTY
backend (native POSIX / ConPTY).

## Development

```bash
go build ./...
GOOS=windows go build ./...
go vet ./...
go test ./...                 # everything
go test ./internal/...        # unit + protocol/auth/TLS tests
go test ./tests/ -count=1     # e2e: real binaries, real PTY (needs bin/hssh)
go test ./internal/server/ -count=1 -run TestResume -v
```

Requires Go `1.27.1+` (`go.mod`).

Notes:

- Don't pipe `go test` into `head` — `SIGPIPE` kills the test binary and the
  output misleads. Redirect to a file and `tail` it instead.
- `go test -race` is not supported on `android/arm64` (Termux).
- Never `pkill -f <pattern>` from the same shell — the pattern matches your
  own command line. Kill by exact PID instead.

## Limitations

- Windows uses ConPTY: it cross-compiles, but on-device testing is not done here.
- No browser client, no file transfer, no port forwarding in v1 (by design).

## License

MIT — see [LICENSE](LICENSE).
