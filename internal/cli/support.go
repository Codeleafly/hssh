package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/hssh/hssh/internal/client"
	"github.com/hssh/hssh/internal/pty"
	"github.com/hssh/hssh/internal/wsx"
)

// yellowStyle is the accent used for warning boxes; ui exposes the escape
// codes indirectly so the CLI does not hard-code them.
const yellowStyle = "\x1b[33m"

const wsxProtocol = wsx.ProtocolSubprotocol

func shutdownContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// restoreOnPanic guarantees the local terminal is restored even if the session
// panics. A client that leaves the shell in raw mode is worse than a crash.
//
// Call it via `defer restoreOnPanic(cl)` so recover() runs in the panicking
// goroutine; calling it without defer would only check for a panic inside
// itself (which never happens) and catch nothing.
func restoreOnPanic(cl *client.Client) {
	if r := recover(); r != nil {
		cl.Restore()
		fmt.Fprintf(os.Stderr, "\nhssh: internal error: %v\n", r)
		debug.PrintStack()
		os.Exit(1)
	}
}

func goVersion() string { return runtime.Version() }

// ptyBackend names the pseudo-terminal implementation in use, so `hssh
// version` documents what a session is actually backed by.
func ptyBackend() string {
	if !pty.Supported() {
		return "unsupported on this platform"
	}
	if runtime.GOOS == "windows" {
		return "ConPTY (Windows pseudo console)"
	}
	return fmt.Sprintf("native POSIX PTY (%s/%s)", runtime.GOOS, runtime.GOARCH)
}
