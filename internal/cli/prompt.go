package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hssh/hssh/internal/ui"

	"golang.org/x/term"
)

// Confirm asks a yes/no question on the terminal.
//
// It reads from /dev/tty when possible so the prompt is not corrupted by a
// piped stdin, and it restores the terminal afterwards even if reading fails.
func Confirm(p *ui.Printer, question string, def bool) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// No controlling terminal (CI, service, container): fall back to
		// stdin, and if that is not a terminal either, refuse to guess.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return false, fmt.Errorf("%s (no terminal available to ask; pass the flag instead)", question)
		}
		return confirmOn(p, os.Stdin, os.Stdout, question, def)
	}
	defer tty.Close()
	return confirmOn(p, tty, tty, question, def)
}

func confirmOn(p *ui.Printer, in io.Reader, out io.Writer, question string, def bool) (bool, error) {
	suffix := "[y/N]"
	if def {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(out, "  %s %s %s ", p.Yellow("?"), question, p.Dim(suffix))

	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return def, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	fmt.Fprintln(out)
	switch answer {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	}
	return false, fmt.Errorf("please answer yes or no")
}

// PromptSecret reads a secret with terminal echo disabled, so a password never
// appears on screen or in a scrollback buffer.
func PromptSecret(p *ui.Printer, label string) (string, error) {
	fmt.Fprintf(os.Stderr, "  %s %s ", p.Yellow("?"), label)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Fprintln(os.Stderr)
		return "", fmt.Errorf("cannot read %s without a terminal; use the flag or an environment variable", label)
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
