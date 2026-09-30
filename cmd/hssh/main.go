// Command hssh is an SSH-like remote terminal that carries a real shell over
// HTTP/WebSocket instead of the SSH binary protocol.
//
//	hssh host --port=8080
//	hssh connect=http://localhost:8080
package main

import (
	"os"

	"github.com/hssh/hssh/internal/cli"
)

func main() {
	app := cli.New(os.Stdout, os.Stderr, os.Stdin)
	os.Exit(app.Run(os.Args[1:]))
}
