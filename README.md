# HSSH — a real remote terminal over HTTP/WebSocket

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
- Password or token auth, TLS (`https`/`wss`), plaintext credential refusal.
- Session table (`hssh sessions`), per-session working-directory isolation, idle/session timeouts, heartbeat keepalive.
- Session resume: `hssh host --allow-resume` + `hssh connect --session=<id>`.
- Strict flags: unknown flags are errors, never silently ignored.
- Structured logs with secret redaction.

## Install

Requires Go 1.27+.

```bash
git clone <your-repo-url> hssh
cd hssh
go build -o bin/hssh ./cmd/hssh
```

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
| `--shell` / `-s` | auto | Shell to run (`HSSH_SHELL` / `$SHELL` / well-known list) |
| `--workdir` / `-w` | home | Initial working directory |
| `--password` / `-k` | — | Require a password (client must use `https`/`wss`) |
| `--token` / `-t` | — | Require a token |
| `--tls-cert` / `--tls-key` | — | Serve HTTPS/WSS (must be given together) |
| `--allow-unauthenticated` | false | Skip the no-auth confirmation prompt |
| `--allow-resume` | false | Let clients reattach with `--session=<id>` |
| `--per-session-cwd` | false | Private working directory per session |
| `--max-sessions` | unlimited | Reject new sessions above this count |
| `--idle-timeout` | off | e.g. `30m` — close sessions with no traffic |
| `--session-timeout` | off | Absolute max session lifetime |
| `--heartbeat` | `30s` | Keepalive interval |
| `--output-buffer` | `4M` | Per-session output queue ceiling |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`, `off` |
| `--quiet` / `-q` | false | Silence logs |
| `--generate-token` | — | Print a strong token and exit |

Running without auth prints a warning and asks for confirmation unless
`--allow-unauthenticated` is given.

### `hssh connect` — open a remote shell

```bash
./bin/hssh connect http://127.0.0.1:8080
./bin/hssh connect=https://example.com:8443 --password 's3cret'
HSSH_PASSWORD='s3cret' ./bin/hssh connect https://example.com:8443
./bin/hssh connect https://example.com:8443 --session <id>   # resume
```

| Flag | Meaning |
|---|---|
| `--password` / `--token` | Credential (only sent over `https`/`wss`) |
| `--ca` / `-c` | PEM bundle to verify the server certificate |
| `--insecure` / `-n` | Skip verification (lab only) |
| `--disconnect-key` | Custom escape sequence |
| `--session` | Reattach to a live session (host needs `--allow-resume`) |
| `--timeout` | Connection timeout (default `15s`) |
| `--no-status` | Skip the connection banner |
| `--log-level`, `--quiet` | Client log verbosity |

A password is never taken from the URL. `HSSH_PASSWORD` / `HSSH_TOKEN`
avoid putting secrets in shell history.

### `hssh sessions` — list live sessions

```bash
./bin/hssh sessions http://127.0.0.1:8080
```

Shows id, client, shell, size, age, idle time and traffic. Never shows
credentials or terminal content.

### `hssh token` / `hssh version`

```bash
./bin/hssh token     # strong random token for --token
./bin/hssh version   # version, protocol, Go, PTY backend
```

### Environment variables

| Variable | Meaning |
|---|---|
| `HSSH_PASSWORD` / `HSSH_TOKEN` | Credential for host or client |
| `HSSH_SHELL` | Override shell auto-detection |
| `HSSH_CONFIG` | Path to a JSON host config file |
| `HSSH_LOG_FORMAT=json` | Structured logs |
| `NO_COLOR` | Disable colour output |

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

- Discovery: `GET /health` → `{name, version, protocol, auth, tls, endpoints}`.
- Terminal: `GET /connect` upgraded to WebSocket, subprotocol `hssh.v1`.
- Every WebSocket frame is `[1 byte opcode][payload]`.
  Binary frames carry raw terminal bytes (no JSON/base64);
  text frames carry JSON control messages
  (`hello`, `auth`, `auth_result`, `terminal_start`, `input`, `resize`,
  `signal`, `exit`, `session_info`, `disconnect`, `error`, `ping`, `pong`,
  `sessions_request`, `sessions_list`).
- Handshake order per connection: `hello` → `auth_result` (challenge) →
  `auth` → `auth_result` (ok) → `terminal_start` (or `sessions_request`,
  or a `resume` id inside `auth`).

## Project layout

```text
cmd/hssh/          entrypoint
internal/
  protocol/        opcodes, codec, message types
  pty/             real PTY (unix / windows / unsupported)
  shell/           shell resolution + filtered environment
  terminal/        server PTY session, pumps, escape parser, raw mode
  auth/            password/token verifier (stateless)
  config/          flags + JSON file + validation
  wsx/             hardened WebSocket wrapper (limits, origin, TLS)
  httpapi/         /health, /, /connect
  server/          host, handshake, session lifecycle, resume
  client/          dial, auth, raw-mode loops, sessions query
  cli/             commands, flag parser, prompts, output
  ui/              terminal printer
  sessions/        session registry
  logging/         redacting structured logger
tests/             e2e: real binaries driven through a real PTY
```

## Development

```bash
go build ./...
GOOS=windows go build ./...
go vet ./...
go test ./internal/...        # unit + protocol/auth/TLS tests
go test ./tests/ -count=1     # e2e: real binaries, real PTY
go test ./internal/server/ -count=1 -run TestResume -v
```

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
