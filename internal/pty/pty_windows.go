//go:build windows

package pty

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const supported = true

// windowsPTY drives a Windows ConPTY (pseudo console). ConPTY is a real
// console host: conhost.exe renders the screen and the child process sees a
// genuine console, so PowerShell, cmd.exe, python, vim and friends behave
// interactively.
type windowsPTY struct {
	proc    *os.Process
	pid     int
	hPC     windows.Handle
	inW     *os.File
	outR    *os.File
	mu      sync.Mutex
	closed  bool
	pcClose bool

	// handle for the process object, so we can query the exit code after the
	// process handle is released.
	hProcess windows.Handle
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !fi.IsDir()
}

func openPlatform(opts OpenOptions) (PTY, error) {
	bin := opts.Command
	if bin == "" {
		bin, _ = lookup(opts.OnWindows)
	}
	if bin == "" {
		return nil, errors.New("pty: no shell executable found (tried COMSPEC, powershell.exe, pwsh.exe)")
	}

	// Pipe A: client -> console input.  ConPTY reads A.r, we write A.w.
	// Pipe B: console output -> client. ConPTY writes B.w, we read B.r.
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}

	size := windows.Coord{X: int16(opts.Winsize.Cols), Y: int16(opts.Winsize.Rows)}
	var hPC windows.Handle
	if err := windows.CreatePseudoConsole(size, windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), 0, &hPC); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("pty: CreatePseudoConsole: %w", err)
	}

	// The parent must drop the ConPTY-side ends, otherwise the pipes never
	// report EOF.
	inR.Close()
	outW.Close()

	p := &windowsPTY{
		hPC:      hPC,
		inW:      inW,
		outR:     outR,
		hProcess: 0,
	}

	if err := p.spawn(bin, opts); err != nil {
		windows.ClosePseudoConsole(hPC)
		inW.Close()
		outR.Close()
		return nil, err
	}
	return p, nil
}

// spawn creates the child process attached to hPC via
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE.
func (p *windowsPTY) spawn(bin string, opts OpenOptions) error {
	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return fmt.Errorf("pty: NewProcThreadAttributeList: %w", err)
	}
	defer attrList.Delete()

	if err := attrList.Update(
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		unsafe.Pointer(p.hPC),
		unsafe.Sizeof(p.hPC),
	); err != nil {
		return fmt.Errorf("pty: UpdateProcThreadAttribute(pseudoconsole): %w", err)
	}

	si := &windows.StartupInfoEx{}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(*si))
	si.ProcThreadAttributeList = attrList.List()

	argv := append([]string{bin}, opts.Args...)
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return err
	}

	// The child inherits the environment we hand it; a nil env means "inherit
	// ours", which would break session isolation, so always pass an explicit one.
	envPtr, err := envBlockPtr(opts.mergeEnv())
	if err != nil {
		return err
	}

	var dirPtr *uint16
	if opts.Dir != "" {
		dirPtr, err = windows.UTF16PtrFromString(opts.Dir)
		if err != nil {
			return err
		}
	}

	var appNamePtr *uint16
	if strings.ContainsAny(bin, `/\:`) {
		appNamePtr, err = windows.UTF16PtrFromString(bin)
		if err != nil {
			return err
		}
	}

	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(
		appNamePtr, cmdLine, nil, nil, false, flags,
		envPtr, dirPtr, &si.StartupInfo, &pi,
	); err != nil {
		return fmt.Errorf("pty: CreateProcess: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	p.hProcess = pi.Process
	p.pid = int(pi.ProcessId)
	return nil
}

// envBlockPtr builds a NUL-separated, double-NUL-terminated UTF-16 environment
// block as required by CreateProcess. Windows requires the block to be sorted
// case-insensitively for some APIs; sorting keeps behaviour predictable.
func envBlockPtr(env []string) (*uint16, error) {
	keys := make(map[string]string, len(env))
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		keys[strings.ToUpper(kv[:i])] = kv
	}
	out := make([]string, 0, len(keys))
	for _, v := range keys {
		out = append(out, v)
	}
	sort.Strings(out)

	var b strings.Builder
	for _, kv := range out {
		b.WriteString(kv)
		b.WriteByte(0)
	}
	b.WriteByte(0) // block terminator
	return windows.UTF16PtrFromString(b.String())
}

func (p *windowsPTY) Read(b []byte) (int, error)  { return p.outR.Read(b) }
func (p *windowsPTY) Write(b []byte) (int, error) { return p.inW.Write(b) }

// Resize calls ResizePseudoConsole, which makes conhost reflow its buffer and
// notify attached clients of a new window size.
func (p *windowsPTY) Resize(ws Winsize) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.pcClose {
		return ErrClosed
	}
	return windows.ResizePseudoConsole(p.hPC, windows.Coord{
		X: int16(ws.Cols),
		Y: int16(ws.Rows),
	})
}

func (p *windowsPTY) Pid() int { return p.pid }

func (p *windowsPTY) Name() string { return fmt.Sprintf("ConPTY:%d", p.pid) }

func (p *windowsPTY) IsWindows() bool { return true }

// Close tears the console down. Closing the ConPTY sends the equivalent of a
// console close event to the attached client processes.
func (p *windowsPTY) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	if !p.pcClose {
		p.pcClose = true
		windows.ClosePseudoConsole(p.hPC)
	}
	p.mu.Unlock()
	return nil
}

// Terminate has no POSIX signal semantics on Windows; every interactive
// control character is delivered as an input byte instead (ConPTY translates
// Ctrl+C into a console control event for the attached client). A non-zero
// signal therefore maps to TerminateProcess.
func (p *windowsPTY) Terminate(sig int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.hProcess == 0 {
		return ErrClosed
	}
	if sig == 0 {
		return nil
	}
	return windows.TerminateProcess(p.hProcess, uint32(sig))
}

// ExitCode blocks until the child exits and returns its exit code. It is used
// by the session to report terminal_exit to the client.
func (p *windowsPTY) ExitCode() int {
	p.mu.Lock()
	h := p.hProcess
	p.mu.Unlock()
	if h == 0 {
		return -1
	}
	_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
	var code uint32
	_ = windows.GetExitCodeProcess(h, &code)
	return int(code)
}
