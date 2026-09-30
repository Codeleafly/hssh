package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hssh/hssh/internal/auth"
	"github.com/hssh/hssh/internal/client"
	"github.com/hssh/hssh/internal/config"
	"github.com/hssh/hssh/internal/logging"
	"github.com/hssh/hssh/internal/protocol"
	"github.com/hssh/hssh/internal/server"
	"github.com/hssh/hssh/internal/sessions"
	"github.com/hssh/hssh/internal/terminal"
	"github.com/hssh/hssh/internal/ui"
	"golang.org/x/term"
)

// App is the hssh command line application.
type App struct {
	Out io.Writer
	Err io.Writer
	In  *os.File

	printer *ui.Printer
	log     *logging.Logger
}

// New builds an application writing to the given streams.
func New(out, errW io.Writer, in *os.File) *App {
	return &App{Out: out, Err: errW, In: in, printer: ui.New(out)}
}

// Run executes a command line and returns the process exit code.
func (a *App) Run(argv []string) int {
	if len(argv) == 0 {
		a.printHelp()
		return 2
	}

	// `hssh connect=http://host:8080` is a first-class form, not a typo.
	cmd := argv[0]
	inline := ""
	if i := strings.IndexByte(cmd, '='); i > 0 {
		inline = cmd[i+1:]
		cmd = cmd[:i]
	}
	rest := argv[1:]

	switch cmd {
	case "host", "serve":
		return a.runHost(rest)
	case "connect":
		if inline != "" {
			rest = append([]string{inline}, rest...)
		}
		return a.runConnect(rest)
	case "sessions":
		return a.runSessions(rest)
	case "version":
		a.printVersion()
		return 0
	case "help", "-h", "--help":
		a.printHelp()
		return 0
	case "token":
		return a.runGenerateToken(rest)
	}

	a.errf("unknown command %q", cmd)
	a.errf("Run 'hssh help' to see the available commands.")
	return 2
}

// ---------------------------------------------------------------- host

func (a *App) runHost(argv []string) int {
	f, err := Parse(argv, hostFlags)
	if err != nil {
		if errors.Is(err, ErrHelp) {
			a.printHostHelp()
			return 0
		}
		a.errf("%v", err)
		return 2
	}
	p := a.printer

	if f.Bool("generate-token") {
		return a.runGenerateToken(nil)
	}

	// Load the JSON file first so explicit flags (and env secrets) always
	// win over the file. The previous order validated and prompted before
	// the file was merged, letting a file silently downgrade auth.
	fileBase, err := config.LoadHostFile(&config.HostConfig{})
	if err != nil {
		a.errf("%v", err)
		return 2
	}

	cfg := &config.HostConfig{
		Host:    fileBase.Host,
		Shell:   fileBase.Shell,
		WorkDir: fileBase.WorkDir,
		TLSCert: fileBase.TLSCert,
		TLSKey:  fileBase.TLSKey,
		// Bools default from file; flags override below when present.
		AllowUnauthenticated: fileBase.AllowUnauthenticated,
		AllowResume:          fileBase.AllowResume,
		PerSessionCwd:        fileBase.PerSessionCwd,
		LogLevel:             fileBase.LogLevel,
		Port:                 fileBase.Port,
		MaxSessions:          fileBase.MaxSessions,
		Heartbeat:            fileBase.Heartbeat,
		IdleTimeout:          fileBase.IdleTimeout,
		SessionTimeout:       fileBase.SessionTimeout,
		OutputBuffer:         fileBase.OutputBuffer,
		MaxFrameSize:         fileBase.MaxFrameSize,
		AuthMode:             fileBase.AuthMode,
	}
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	// Flags win over the file when explicitly given.
	if f.Has("host") {
		cfg.Host = f.String("host", cfg.Host)
	}
	if f.Has("shell") {
		cfg.Shell = f.String("shell", cfg.Shell)
	}
	if f.Has("workdir") {
		cfg.WorkDir = f.String("workdir", cfg.WorkDir)
	}
	if f.Has("tls-cert") {
		cfg.TLSCert = f.String("tls-cert", cfg.TLSCert)
	}
	if f.Has("tls-key") {
		cfg.TLSKey = f.String("tls-key", cfg.TLSKey)
	}
	if f.Has("log-level") {
		cfg.LogLevel = f.String("log-level", cfg.LogLevel)
	}
	if f.Has("allow-unauthenticated") {
		cfg.AllowUnauthenticated = f.Bool("allow-unauthenticated")
	}
	if f.Has("allow-resume") {
		cfg.AllowResume = f.Bool("allow-resume")
	}
	if f.Has("per-session-cwd") {
		cfg.PerSessionCwd = f.Bool("per-session-cwd")
	}
	// Credentials: flag > env > file.
	if f.Has("password") {
		cfg.Password = f.String("password", "")
	} else if v := os.Getenv("HSSH_PASSWORD"); v != "" {
		cfg.Password = v
	} else {
		cfg.Password = fileBase.Password
	}
	if f.Has("token") {
		cfg.Token = f.String("token", "")
	} else if v := os.Getenv("HSSH_TOKEN"); v != "" {
		cfg.Token = v
	} else {
		cfg.Token = fileBase.Token
	}

	if f.Has("port") {
		if cfg.Port, err = f.Int("port", 8080); err != nil {
			a.errf("%v", err)
			return 2
		}
	} else if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if f.Has("max-sessions") {
		if cfg.MaxSessions, err = f.Int("max-sessions", 0); err != nil {
			a.errf("%v", err)
			return 2
		}
	}
	if f.Has("heartbeat") {
		if cfg.Heartbeat, err = f.Duration("heartbeat", 30*time.Second); err != nil {
			a.errf("%v", err)
			return 2
		}
	} else if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 30 * time.Second
	}
	if f.Has("idle-timeout") {
		if cfg.IdleTimeout, err = f.Duration("idle-timeout", 0); err != nil {
			a.errf("%v", err)
			return 2
		}
	}
	if f.Has("session-timeout") {
		if cfg.SessionTimeout, err = f.Duration("session-timeout", 0); err != nil {
			a.errf("%v", err)
			return 2
		}
	}
	if f.Has("output-buffer") {
		v := f.String("output-buffer", "")
		n, err := config.ParseSize(v)
		if err != nil {
			a.errf("--output-buffer: %v", err)
			return 2
		}
		cfg.OutputBuffer = n
	}

	// The security gate. Running a world-reachable shell with no
	// authentication must be a deliberate decision, so it is confirmed unless
	// the operator opted in explicitly. This runs AFTER the file merge so a
	// file cannot silently downgrade auth.
	// An explicit "auth" value from the file is honoured; otherwise infer
	// from the effective credentials.
	if cfg.AuthMode == "" {
		cfg.AuthMode = config.AuthNone
	}
	if cfg.AuthMode == config.AuthNone {
		if cfg.Password != "" {
			cfg.AuthMode = config.AuthPassword
		} else if cfg.Token != "" {
			cfg.AuthMode = config.AuthToken
		}
	}
	needConfirm := cfg.AuthMode == config.AuthNone && !cfg.AllowUnauthenticated
	if needConfirm {
		if !a.confirmUnauthenticated(cfg) {
			a.errf("Aborted: the host was not started without authentication.")
			a.errf("Start it again with --allow-unauthenticated to accept the risk,")
			a.errf("or set --password / --token to require credentials.")
			return 1
		}
		cfg.AllowUnauthenticated = true
	}

	if err := cfg.Validate(); err != nil {
		a.errf("%v", err)
		return 2
	}

	if f.Bool("quiet") {
		cfg.LogLevel = "off"
	}
	log := logging.New(a.Err, mustLevel(cfg.LogLevel), os.Getenv("HSSH_LOG_FORMAT") == "json")
	a.log = log

	host, err := server.New(server.Options{Config: cfg, Log: log})
	if err != nil {
		a.errf("Could not start the HSSH host")
		a.errf("")
		a.errf("  Reason: %v", err)
		return 1
	}

	addr, err := host.Start()
	if err != nil {
		a.errf("Could not bind %s", cfg.Addr())
		a.errf("")
		a.errf("  Reason: %v", err)
		a.errf("")
		a.errf("  Another process may already be using that port.")
		return 1
	}

	a.printHostBanner(host, addr, cfg)

	// Graceful shutdown: SIGINT/SIGTERM close every PTY and reap every shell.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Fprintln(a.Out)
		p.Info(fmt.Sprintf("Received %s, shutting down", sig))
		for _, s := range host.Sessions().All() {
			p.Info("Closing session " + shortID(s.ID()))
		}
		ctx, cancel := shutdownContext(3 * time.Second)
		defer cancel()
		_ = host.Shutdown(ctx)
	}()

	host.Wait()
	fmt.Fprintln(a.Out)
	p.Success("Host stopped cleanly")
	return 0
}

// confirmUnauthenticated prints the security warning and asks for consent.
func (a *App) confirmUnauthenticated(cfg *config.HostConfig) bool {
	p := a.printer
	lines := []string{
		p.Bold("WARNING: authentication is disabled."),
		"",
		"Anyone who can reach this host can open a remote shell",
		"with the same privileges as the user running it.",
	}
	lines = append(lines, p.Dim(strings.Repeat("─", 44)))
	if cfg.TLSEnabled() {
		lines = append(lines,
			"Transport: TLS is ENABLED, so keystrokes and output are",
			"encrypted in transit, but there is still no authentication.",
		)
	} else {
		lines = append(lines,
			p.Yellow("Transport: PLAIN HTTP. Everything you type and"),
			p.Yellow("everything the shell prints travels unencrypted."),
			p.Yellow("Anyone on the network path can read and alter it."),
		)
	}
	lines = append(lines, "",
		p.Dim("Use this only on a trusted, isolated network."))

	p.Blank()
	p.Box(lines, p.Style(yellowStyle, ""))
	p.Blank()

	ok, err := Confirm(p, "Start the host without authentication?", false)
	if err != nil {
		a.errf("Could not read the confirmation: %v", err)
		return false
	}
	return ok
}

func (a *App) printHostBanner(h *server.Host, addr string, cfg *config.HostConfig) {
	p := a.printer
	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	display := displayAddr(addr, cfg.Host)

	p.Title("HSSH", protocol.VersionString)
	p.Blank()
	p.Success("Listening on " + p.Bold(display))
	p.Success("WebSocket endpoint ready at " + p.Bold(scheme+"://"+display+"/connect"))
	p.Field("shell", p.Cyan(h.Shell().Label)+p.Grey("  "+h.Shell().Path))
	p.Field("working dir", h.WorkDir())
	if cfg.PerSessionCwd {
		p.Field("isolation", "one private working directory per session")
	}
	if cfg.MaxSessions > 0 {
		p.Field("session limit", fmt.Sprint(cfg.MaxSessions))
	} else {
		p.Field("session limit", "unlimited")
	}
	if cfg.IdleTimeout > 0 {
		p.Field("idle timeout", cfg.IdleTimeout.String())
	}
	p.Blank()

	p.Section("Security")
	switch cfg.AuthMode {
	case config.AuthPassword:
		p.Success("Password authentication is enabled")
		if cfg.TLSEnabled() {
			p.Success("TLS is enabled (HTTPS / WSS)")
		} else {
			p.Failure("TLS is disabled: clients will refuse to send the password over plain HTTP")
		}
	case config.AuthToken:
		p.Success("Token authentication is enabled")
		if cfg.TLSEnabled() {
			p.Success("TLS is enabled (HTTPS / WSS)")
		} else {
			p.Failure("TLS is disabled: clients will refuse to send the token over plain HTTP")
		}
	default:
		p.Warn("Authentication is disabled")
		if cfg.TLSEnabled() {
			p.Warn("TLS is enabled, so the stream is encrypted but unauthenticated")
		} else {
			p.Warn("TLS is disabled: the terminal stream is unencrypted")
		}
	}
	if cfg.TLSEnabled() {
		p.Field("certificate", cfg.TLSCert)
	}
	if os.Geteuid() != 0 {
		p.Field("privileges", "unprivileged user; the host needs no root access")
	} else {
		p.Warn("running as root: every session is a root shell")
	}
	p.Blank()

	p.Section("Connect")
	p.Command("hssh", "connect="+scheme+"://"+display)
	p.Command("hssh", "connect="+scheme+"://"+display+" --password=...")
	p.Blank()
	p.Println(p.Dim("Waiting for connections..."))
}

// ---------------------------------------------------------------- connect

func (a *App) runConnect(argv []string) int {
	f, err := Parse(argv, sessionFlags)
	if err != nil {
		if errors.Is(err, ErrHelp) {
			a.printConnectHelp()
			return 0
		}
		a.errf("%v", err)
		return 2
	}
	target := f.Arg(0)
	if target == "" {
		target = f.String("url", f.String("server", ""))
	}
	if target == "" {
		a.errf("No server address given.")
		a.errf("")
		a.errf("  Usage: hssh connect=http://host:8080")
		a.errf("          hssh connect http://host:8080")
		return 2
	}
	target = strings.TrimSuffix(target, "/")

	cfg := &config.ClientConfig{
		URL:           target,
		Password:      f.String("password", ""),
		Token:         f.String("token", ""),
		CAFile:        f.String("ca", ""),
		ResumeSession: f.String("session", ""),
		Cwd:           f.String("cwd", ""),
		Insecure:      f.Bool("insecure"),
		Timeout:       15 * time.Second,
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("HSSH_PASSWORD")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("HSSH_TOKEN")
	}
	if cfg.Timeout, err = f.Duration("timeout", cfg.Timeout); err != nil {
		a.errf("%v", err)
		return 2
	}
	if f.Has("disconnect-key") {
		seq, err := terminal.ParseEscapeKey(f.String("disconnect-key", ""))
		if err != nil {
			a.errf("--disconnect-key: %v", err)
			return 2
		}
		cfg.Disconnect = []string{string(seq)}
	}
	if v := f.String("term", ""); v != "" {
		os.Setenv("TERM", v)
	}

	scheme := "http"
	if strings.HasPrefix(strings.ToLower(target), "https://") ||
		strings.HasPrefix(strings.ToLower(target), "wss://") {
		scheme = "https"
	}
	cfg.TLS = scheme == "https"
	cfg.Host = hostOf(target)

	log := logging.New(a.Err, mustLevel(f.String("log-level", "warn")), os.Getenv("HSSH_LOG_FORMAT") == "json")
	if f.Bool("quiet") {
		log = logging.Discard()
	}
	a.log = log

	// The local terminal must exist; raw mode is unavoidable for a real
	// interactive session.
	size, err := terminal.SizeOf(a.In)
	if err != nil {
		a.errf("Cannot read the local terminal size: %v", err)
		a.errf("HSSH needs a real terminal on stdin. It does not emulate one.")
		return 1
	}
	if !term.IsTerminal(int(a.In.Fd())) {
		a.errf("stdin is not a terminal.")
		a.errf("HSSH connects to a live PTY and needs an interactive terminal.")
		return 1
	}

	cl, err := client.New(client.Options{Config: cfg, Log: log, In: a.In, Out: a.Out})
	if err != nil {
		a.errf("%v", err)
		return 1
	}

	// If the host demands a password and none was supplied, ask for it without
	// echoing. The check happens after discovery, inside Connect.
	if err := cl.Connect(); err != nil {
		var ce *client.ConnectError
		if errors.As(err, &ce) {
			a.errf("")
			a.errf("%s", ce.Error())
			if errors.Is(err, client.ErrAuthFailed) && cfg.Password == "" && cfg.Token == "" {
				a.errf("  The host requires a credential. Re-run with --password=... or")
				a.errf("  set HSSH_PASSWORD, and use https:// so it is not sent in the clear.")
			}
			return 1
		}
		a.errf("Could not connect: %v", err)
		return 1
	}

	if f.Bool("no-status") {
		// Fall through straight into the session.
	} else {
		a.printConnectBanner(cl, cfg)
	}

	// A panic or a signal must never leave the terminal in raw mode.
	defer cl.Restore()
	defer restoreOnPanic(cl)

	if err := cl.Start(size); err != nil {
		a.printer.Blank()
		if wsxClosed(err) {
			a.printer.Info("Disconnected")
			return 0
		}
		a.printer.Failure("Session ended: " + err.Error())
		return 1
	}

	cl.Restore()
	cl.Wait()
	a.printer.Blank()

	if st, ok := cl.ExitStatus(); ok {
		if st.Signal != "" {
			a.printer.Info(fmt.Sprintf("Remote shell terminated by %s", st.Signal))
		} else {
			a.printer.Info(fmt.Sprintf("Remote shell exited with status %d", st.Code))
		}
	} else {
		a.printer.Info("Disconnected")
	}
	return 0
}

func (a *App) printConnectBanner(cl *client.Client, cfg *config.ClientConfig) {
	p := a.printer
	target := strings.TrimPrefix(strings.TrimPrefix(cfg.URL, "https://"), "http://")
	p.Success("Connected to " + p.Bold(target))
	if cl.Detected != nil {
		p.Field("host version", cl.Detected.Version)
		p.Field("protocol", cl.Detected.Protocol)
		p.Field("auth", cl.Detected.Auth)
	}
	p.Field("transport", transportName(cfg.TLS))
	p.Field("disconnect", "Ctrl+]  or  ~.")
	p.Blank()
}

// ---------------------------------------------------------------- sessions

func (a *App) runSessions(argv []string) int {
	f, err := Parse(argv, connectFlags)
	if err != nil {
		if errors.Is(err, ErrHelp) {
			p := a.printer
			p.Title("hssh sessions", protocol.VersionString)
			p.Println(p.Dim("Show the live terminal sessions of an HSSH host."))
			p.Blank()
			p.Command("hssh", "sessions http://server:8080")
			p.Blank()
			p.Field("--password", "password, sent only over https/wss")
			p.Field("--token", "token, sent only over https/wss")
			p.Field("--ca", "PEM bundle for server certificate verification")
			p.Field("--insecure", "skip certificate verification (lab use only)")
			p.Field("--url / --server", "host URL (default http://localhost:8080)")
			p.Field("--timeout", "connection timeout (default 15s)")
			p.Field("--log-level", "debug, info, warn, error, off")
			p.Field("--quiet", "silence logs")
			p.Field("--no-color", "disable colour output")
			p.Blank()
			return 0
		}
		a.errf("%v", err)
		return 2
	}
	p := a.printer

	target := f.Arg(0)
	if target == "" {
		target = f.String("url", "http://localhost:8080")
	}
	target = strings.TrimSuffix(target, "/")

	cfg := &config.ClientConfig{
		URL:      target,
		Password: f.String("password", ""),
		Token:    f.String("token", ""),
		CAFile:   f.String("ca", ""),
		Insecure: f.Bool("insecure"),
		Timeout:  15 * time.Second,
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("HSSH_PASSWORD")
	}
	if cfg.Token == "" {
		cfg.Token = os.Getenv("HSSH_TOKEN")
	}
	cfg.TLS = strings.HasPrefix(strings.ToLower(target), "https://") ||
		strings.HasPrefix(strings.ToLower(target), "wss://")
	cfg.Host = hostOf(target)

	log := logging.Discard()
	cl, err := client.New(client.Options{Config: cfg, Log: log, In: a.In, Out: a.Out})
	if err != nil {
		a.errf("%v", err)
		return 1
	}
	if err := cl.Connect(); err != nil {
		var ce *client.ConnectError
		if errors.As(err, &ce) {
			a.errf("")
			a.errf("%s", ce.Error())
			return 1
		}
		a.errf("Could not connect: %v", err)
		return 1
	}
	defer cl.Close()

	list, err := cl.QuerySessions()
	if err != nil {
		a.errf("Could not read the session table: %v", err)
		return 1
	}

	p.Title("HSSH sessions", protocol.VersionString)
	p.Field("host", p.Bold(strings.TrimPrefix(strings.TrimPrefix(cfg.URL, "https://"), "http://")))
	p.Field("transport", transportName(cfg.TLS))
	if list.Max > 0 {
		p.Field("session limit", fmt.Sprintf("%d", list.Max))
	} else {
		p.Field("session limit", "unlimited")
	}
	p.Blank()

	rows := make([][]string, 0, len(list.Sessions))
	for _, s := range list.Sessions {
		size := "-"
		if s.Cols > 0 && s.Rows > 0 {
			size = fmt.Sprintf("%dx%d", s.Cols, s.Rows)
		}
		shell := s.Shell
		if shell == "" {
			shell = "-"
		}
		cwd := s.Cwd
		if cwd == "" {
			cwd = "-"
		}
		id := shortID(s.ID)
		if s.Self {
			id += " (this one)"
		}
		rows = append(rows, []string{
			id,
			s.Client,
			shell,
			cwd,
			size,
			age(s.Created),
			idle(s.LastSeen),
			formatBytes(s.BytesIn) + " in / " + formatBytes(s.BytesOut) + " out",
		})
	}
	p.Table([]string{"ID", "CLIENT", "SHELL", "CWD", "SIZE", "AGE", "IDLE", "TRAFFIC"}, rows)
	p.Blank()
	if len(rows) == 0 {
		p.Println(p.Dim("  No active sessions."))
		p.Blank()
	}
	return 0
}

// age renders a duration since t, rounded to something readable.
func age(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDuration(time.Since(t))
}

func idle(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDuration(time.Since(t))
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}

// ---------------------------------------------------------------- misc

func (a *App) runGenerateToken(argv []string) int {
	tok, err := auth.GenerateToken()
	if err != nil {
		a.errf("Could not generate a token: %v", err)
		return 1
	}
	a.printer.Println(tok)
	return 0
}

func (a *App) printVersion() {
	p := a.printer
	p.Title("HSSH", protocol.VersionString)
	p.Blank()
	p.Field("protocol", protocol.Version)
	p.Field("websocket subprotocol", wsxProtocol)
	p.Field("go", goVersion())
	p.Field("pty", ptyBackend())
	p.Blank()
}

func (a *App) printHelp() {
	p := a.printer
	p.Title("HSSH", protocol.VersionString)
	p.Println(p.Dim("An SSH-like remote terminal over HTTP/WebSocket, backed by a real PTY."))
	p.Blank()

	p.Section("Usage")
	p.Command("hssh host", "--port=8080 [options]")
	p.Command("hssh connect", "http://server:8080 [--password=...]")
	p.Command("hssh sessions", "")
	p.Command("hssh token", "generate a strong authentication token")
	p.Command("hssh version", "")
	p.Blank()

	p.Section("Examples")
	p.Command("hssh", "host --port=8080 --allow-unauthenticated")
	p.Command("hssh", "host --port=8443 --tls-cert=server.crt --tls-key=server.key --password=secret")
	p.Command("hssh", "connect=http://localhost:8080")
	p.Command("hssh", "connect=https://server:8443 --password=secret")
	p.Blank()

	p.Section("Host options")
	p.Field("--host", "address to bind (default 0.0.0.0)")
	p.Field("--port", "port to listen on (default 8080)")
	p.Field("--shell", "shell to run, e.g. bash, zsh, pwsh (default: auto-detect)")
	p.Field("--workdir", "initial working directory (default: your home)")
	p.Field("--per-session-cwd", "give every session its own working directory")
	p.Field("--password", "require a password (implies https on the client)")
	p.Field("--token", "require a token (implies https on the client)")
	p.Field("--max-sessions", "reject new sessions above this count (0 = unlimited)")
	p.Field("--tls-cert / --tls-key", "serve HTTPS / WSS")
	p.Field("--idle-timeout", "close sessions with no input, e.g. 30m")
	p.Field("--session-timeout", "absolute maximum session lifetime")
	p.Field("--heartbeat", "keepalive interval (default 30s)")
	p.Field("--output-buffer", "per-session output queue ceiling, e.g. 4M")
	p.Field("--allow-unauthenticated", "skip the no-auth confirmation prompt")
	p.Field("--allow-resume", "let clients reattach with --session=<id>")
	p.Field("--log-level", "debug, info, warn, error, off (default info)")
	p.Field("--quiet", "silence logs")
	p.Field("--no-color", "disable colour output")
	p.Field("--generate-token", "print a strong token and exit (same as hssh token)")
	p.Blank()

	p.Section("Connect options")
	p.Field("--password", "password to send over the encrypted channel")
	p.Field("--token", "token to send over the encrypted channel")
	p.Field("--ca", "PEM bundle used to verify the server certificate")
	p.Field("--insecure", "skip certificate verification (lab use only)")
	p.Field("--disconnect-key", "escape sequence that ends the session (default Ctrl+] and ~.)")
	p.Field("--timeout", "connection timeout (default 15s)")
	p.Field("--term", "TERM to request (default $TERM or xterm-256color)")
	p.Field("--url / --server", "alternate spellings for the target URL")
	p.Field("--session", "reattach to a live session by id")
	p.Field("--cwd", "start in this server directory (default: host working dir)")
	p.Field("--no-status", "skip the connection banner")
	p.Field("--log-level", "debug, info, warn, error, off (default warn)")
	p.Field("--quiet", "silence logs")
	p.Field("--no-color", "disable colour output")
	p.Blank()

	p.Section("While connected")
	p.Field("Ctrl+C / Ctrl+D", "sent to the remote shell, not to the local client")
	p.Field("Ctrl+]", "disconnect cleanly")
	p.Field("~.", "disconnect, typed at the start of a line")
	p.Field("resize", "sent to the server automatically, for vim, top and less")
	p.Blank()

	p.Section("Environment")
	p.Field("HSSH_PASSWORD", "password for the host or the client")
	p.Field("HSSH_TOKEN", "token for the host or the client")
	p.Field("HSSH_SHELL", "override the auto-detected shell")
	p.Field("HSSH_CONFIG", "path to a JSON config file (else ./hssh.json, ~/.hssh/host.json)")
	p.Field("HSSH_DIR", "single HSSH home for sessions/history (default ~/.hssh)")
	p.Field("HSSH_LOG_FORMAT", "set to json for structured logs")
	p.Field("NO_COLOR", "disable colour output")
	p.Field("HSSH_ASCII", "set to 1 for ASCII output")
	p.Blank()
}

func (a *App) printHostHelp() {
	p := a.printer
	p.Title("hssh host", protocol.VersionString)
	p.Println(p.Dim("Start an HSSH host that serves real shells over WebSocket."))
	p.Blank()
	p.Command("hssh host", "--port=8080")
	p.Blank()
	p.Field("--port", "port to listen on (default 8080)")
	p.Field("--host", "bind address (default 0.0.0.0)")
	p.Field("--shell", "shell to run (default: $SHELL, then bash/zsh/sh)")
	p.Field("--workdir", "initial working directory (default: home)")
	p.Field("--password", "require a password")
	p.Field("--token", "require a token")
	p.Field("--allow-unauthenticated", "do not ask before running without auth")
	p.Field("--max-sessions", "maximum concurrent sessions (0 = unlimited)")
	p.Field("--tls-cert", "PEM certificate for HTTPS/WSS")
	p.Field("--tls-key", "PEM private key for HTTPS/WSS")
	p.Field("--per-session-cwd", "isolate each session's working directory")
	p.Field("--allow-resume", "let a client reattach with --session=<id>")
	p.Field("--idle-timeout", "close sessions with no input, e.g. 30m")
	p.Field("--session-timeout", "absolute maximum session lifetime")
	p.Field("--heartbeat", "keepalive interval (default 30s)")
	p.Field("--output-buffer", "per-session output queue ceiling, e.g. 4M")
	p.Field("--log-level", "debug, info, warn, error, off")
	p.Field("--quiet", "silence logs")
	p.Field("--no-color", "disable colour output")
	p.Field("--generate-token", "print a strong token and exit")
	p.Blank()
	p.Println("  " + p.Dim("Run 'hssh help' for the full list."))
	p.Blank()
}

func (a *App) printConnectHelp() {
	p := a.printer
	p.Title("hssh connect", protocol.VersionString)
	p.Println(p.Dim("Connect to an HSSH host and open its shell in this terminal."))
	p.Blank()
	p.Command("hssh connect", "http://localhost:8080")
	p.Command("hssh connect", "https://server:8443 --password=secret")
	p.Blank()
	p.Field("--password", "password, sent only over https/wss")
	p.Field("--token", "token, sent only over https/wss")
	p.Field("--ca", "PEM bundle for server certificate verification")
	p.Field("--insecure", "skip certificate verification (lab use only)")
	p.Field("--disconnect-key", "escape sequence that disconnects (default Ctrl+] and ~.)")
	p.Field("--timeout", "connection timeout (default 15s)")
	p.Field("--term", "TERM to request (default $TERM or xterm-256color)")
	p.Field("--url / --server", "alternate spellings for the target URL")
	p.Field("--session", "reattach to a live session by id (needs --allow-resume)")
	p.Field("--cwd", "start in this server directory (default: host working dir)")
	p.Field("--no-status", "do not print the connection banner")
	p.Field("--log-level", "debug, info, warn, error, off (default warn)")
	p.Field("--quiet", "silence logs")
	p.Field("--no-color", "disable colour output")
	p.Blank()
}

// ---------------------------------------------------------------- helpers

func (a *App) errf(format string, args ...any) {
	fmt.Fprintf(a.Err, format+"\n", args...)
}

func mustLevel(s string) logging.Level {
	l, err := logging.ParseLevel(s)
	if err != nil {
		return logging.LevelInfo
	}
	return l
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// displayAddr renders a listen address for humans. Binding to 0.0.0.0 or the
// unspecified IPv6 address is shown as ":port", which is what people type.
func displayAddr(bound, configured string) string {
	host, port, err := net.SplitHostPort(bound)
	if err != nil {
		return bound
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		if configured != "" && configured != "0.0.0.0" && configured != "::" {
			return net.JoinHostPort(configured, port)
		}
		return ":" + port
	}
	return net.JoinHostPort(host, port)
}

func hostOf(target string) string {
	s := target
	for _, p := range []string{"https://", "http://", "wss://", "ws://", "hssh://"} {
		// Case-insensitive scheme strip: users paste HTTPS:// too.
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			s = s[len(p):]
			break
		}
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// Prefer proper host:port splitting so IPv6 "[::1]:8080" keeps "::1"
	// without brackets instead of being mangled to "[:".
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	// No port: strip brackets from a bare "[::1]".
	s = strings.Trim(s, "[]")
	// Strip a trailing :port for IPv4/hostname forms only (a single colon).
	if strings.Count(s, ":") == 1 {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			s = s[:i]
		}
	}
	return s
}

func transportName(tls bool) string {
	if tls {
		return "TLS (encrypted)"
	}
	return "plain HTTP (not encrypted)"
}

func wsxClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "closed") || strings.Contains(msg, "EOF")
}

var _ = sessions.ErrNotFound
