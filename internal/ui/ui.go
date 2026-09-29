// Package ui renders HSSH's terminal output.
//
// It stays deliberately restrained: no animation, no cursor tricks, and every
// glyph degrades to ASCII when the output is not a terminal or NO_COLOR is set.
// The same source then looks right in a normal shell, in CI logs, and in a
// pipe to a file.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI styles used by HSSH. Only these, so the palette stays small.
const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
	grey   = "\x1b[90m"
)

// Printer writes styled output to a stream.
type Printer struct {
	w     io.Writer
	color bool
	// unicode enables box drawing and check marks.
	unicode bool
}

// New builds a printer for w, auto-detecting colour and Unicode support.
func New(w io.Writer) *Printer {
	p := &Printer{w: w}
	if f, ok := w.(*os.File); ok {
		p.color = isTerminal(f) && os.Getenv("NO_COLOR") == ""
		p.unicode = p.color && os.Getenv("HSSH_ASCII") == ""
	} else {
		p.color = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != ""
		p.unicode = p.color
	}
	// Windows terminals need the VT processing switch, which Go enables for
	// os.Stdout on Windows 10+; the detection above simply keeps us safe.
	return p
}

// SetColor forces colour on or off.
func (p *Printer) SetColor(on bool) { p.color = on }

func (p *Printer) paint(style, s string) string {
	if !p.color || style == "" {
		return s
	}
	return style + s + reset
}

func (p *Printer) glyph(uni, ascii string) string {
	if p.unicode {
		return uni
	}
	return ascii
}

// Symbols used across the UI.
func (p *Printer) ok() string     { return p.paint(green, p.glyph("✓", "OK")) }
func (p *Printer) fail() string   { return p.paint(red, p.glyph("✗", "x")) }
func (p *Printer) warn() string   { return p.paint(yellow, p.glyph("⚠", "!")) }
func (p *Printer) info() string   { return p.paint(blue, p.glyph("•", "-")) }
func (p *Printer) arrow() string  { return p.paint(cyan, p.glyph("→", "->")) }
func (p *Printer) bullet() string { return p.paint(grey, p.glyph("│", "|")) }

// Printf writes plain text.
func (p *Printer) Printf(format string, a ...any) {
	fmt.Fprintf(p.w, format, a...)
}

// Println writes plain text plus a newline.
func (p *Printer) Println(s string) { fmt.Fprintln(p.w, s) }

// Blank writes an empty line.
func (p *Printer) Blank() { fmt.Fprintln(p.w) }

// Success reports a completed step.
func (p *Printer) Success(msg string) {
	fmt.Fprintf(p.w, "  %s %s\n", p.ok(), msg)
}

// Failure reports a failed step.
func (p *Printer) Failure(msg string) {
	fmt.Fprintf(p.w, "  %s %s\n", p.fail(), msg)
}

// Warn reports a warning.
func (p *Printer) Warn(msg string) {
	fmt.Fprintf(p.w, "  %s %s\n", p.warn(), msg)
}

// Info reports a neutral fact.
func (p *Printer) Info(msg string) {
	fmt.Fprintf(p.w, "  %s %s\n", p.info(), msg)
}

// Step reports work in progress or done, with a dim verb.
func (p *Printer) Step(verb, msg string) {
	fmt.Fprintf(p.w, "  %s %s %s\n", p.paint(green, verb), p.Dim(msg), "")
}

// Title prints a section header.
func (p *Printer) Title(app, version string) {
	fmt.Fprintf(p.w, "%s %s\n", p.paint(bold, app), p.paint(grey, "v"+version))
}

// Command prints a command hint.
func (p *Printer) Command(name, args string) {
	line := "  " + p.arrow() + " " + p.paint(bold, name)
	if args != "" {
		line += " " + args
	}
	fmt.Fprintln(p.w, line)
}

// Section prints a labelled block header with a rule.
func (p *Printer) Section(label string) {
	rule := strings.Repeat("─", 46)
	if p.unicode {
		rule = strings.Repeat("─", 46)
	}
	fmt.Fprintf(p.w, "\n%s\n", p.paint(grey, label+" "+rule))
}

// Field prints an aligned key/value pair.
func (p *Printer) Field(key, value string) {
	fmt.Fprintf(p.w, "  %s %s %s\n", p.bullet(), p.paint(grey, pad(key, 18)), value)
}

// Table prints an aligned table.
func (p *Printer) Table(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Fprintf(p.w, "  %s\n", p.Dim("none"))
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	head := make([]string, len(headers))
	for i, h := range headers {
		head[i] = p.paint(grey, pad(h, widths[i]))
	}
	fmt.Fprintf(p.w, "  %s\n", strings.Join(head, "  "))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = pad(c, widths[i])
		}
		fmt.Fprintf(p.w, "  %s\n", strings.TrimRight(strings.Join(cells, "  "), " "))
	}
}

// Box prints a framed callout, used for the security warning.
func (p *Printer) Box(lines []string, style string) {
	width := 62
	for _, l := range lines {
		// Count printable runes, not bytes, so box drawing lines up for UTF-8.
		if n := len([]rune(l)); n+4 > width {
			width = n + 4
		}
	}
	if width > 78 {
		width = 78
	}
	top, bottom := "┌", "┐"
	botLeft, botRight := "└", "┘"
	left, right := "│", "│"
	if !p.unicode {
		top, bottom = "+", "+"
		botLeft, botRight = "+", "+"
		left, right = "|", "|"
	}
	fmt.Fprintf(p.w, "%s%s%s\n", p.paint(style, top), p.paint(style, strings.Repeat("─", width)), p.paint(style, bottom))
	for _, l := range lines {
		padLen := width - len([]rune(l)) - 2
		if padLen < 0 {
			padLen = 0
		}
		fmt.Fprintf(p.w, "%s %s%s %s\n",
			p.paint(style, left), l, strings.Repeat(" ", padLen), p.paint(style, right))
	}
	fmt.Fprintf(p.w, "%s%s%s\n", p.paint(style, botLeft), p.paint(style, strings.Repeat("─", width)), p.paint(style, botRight))
}

func pad(s string, n int) string {
	l := len([]rune(s))
	if l >= n {
		return s
	}
	return s + strings.Repeat(" ", n-l)
}

// Styles exposed for callers that compose their own lines.
func (p *Printer) Style(style, s string) string { return p.paint(style, s) }

// Print writes a raw string.
func (p *Printer) Print(s string) { fmt.Fprint(p.w, s) }

// Arrow is the right-pointing marker used in command hints.
func (p *Printer) Arrow() string { return p.arrow() }

// Bold styles s.
func (p *Printer) Bold(s string) string { return p.paint(bold, s) }

// Dim styles s.
func (p *Printer) Dim(s string) string { return p.paint(dim, s) }

// Green styles s.
func (p *Printer) Green(s string) string { return p.paint(green, s) }

// Yellow styles s.
func (p *Printer) Yellow(s string) string { return p.paint(yellow, s) }

// Cyan styles s.
func (p *Printer) Cyan(s string) string { return p.paint(cyan, s) }

// Red styles s.
func (p *Printer) Red(s string) string { return p.paint(red, s) }

// Grey styles s.
func (p *Printer) Grey(s string) string { return p.paint(grey, s) }
