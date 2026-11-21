//go:build darwin || linux

package wrapper

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// errFdRange: select(2) cannot watch descriptors at or above FD_SETSIZE.
var errFdRange = errors.New("wrapper: descriptor beyond FD_SETSIZE")

// Signals the wrapper handles.
var (
	sigWINCH os.Signal = syscall.SIGWINCH
	sigCONT  os.Signal = syscall.SIGCONT
	sigTSTP  os.Signal = syscall.SIGTSTP
	// forwarded reach the child (D57): the PTY and direct-mode children
	// lead sessions of their own, so the terminal's signals never reach
	// them directly.
	forwarded = []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP}
)

// sysSignal is a signal number for kill(2).
type sysSignal = syscall.Signal

const (
	sigTerm = syscall.SIGTERM
	sigKill = syscall.SIGKILL
	sigStop = syscall.SIGSTOP
	sigCont = syscall.SIGCONT
)

// fdOf returns the descriptor of f without switching it to blocking mode
// (os.File.Fd would).
func fdOf(f *os.File) (int, error) {
	if f == nil {
		return -1, os.ErrInvalid
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := rc.Control(func(u uintptr) { fd = int(u) }); err != nil {
		return -1, err
	}
	return fd, nil
}

// readFD reads what is available on fd. eof reports a hung-up terminal or
// a PTY whose other side is closed (EIO); n == 0 with a nil error means try
// again.
func readFD(fd int, p []byte) (n int, eof bool, err error) {
	n, err = syscall.Read(fd, p)
	switch {
	case err == syscall.EINTR || err == syscall.EAGAIN:
		return 0, false, nil
	case err == syscall.EIO:
		return 0, true, nil
	case err != nil:
		return 0, false, err
	case n == 0:
		return 0, true, nil
	}
	return n, false, nil
}

// winsize mirrors struct winsize.
type winsize struct {
	Row, Col, X, Y uint16
}

func getWinsize(fd int) (winsize, error) {
	var ws winsize
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); e != 0 {
		return winsize{}, e
	}
	return ws, nil
}

func setWinsize(fd int, ws winsize) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws))); e != 0 {
		return e
	}
	return nil
}

// waitResult is one wait4 outcome.
type waitResult struct {
	exited   bool // normal exit or death by signal
	stopped  bool
	code     int // exit status, or 128+signal
	stopSign syscall.Signal
}

// wait4 waits for pid; with untraced it also returns when pid stops.
func wait4(pid int, untraced bool) (waitResult, error) {
	opts := 0
	if untraced {
		opts = syscall.WUNTRACED
	}
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, opts, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return waitResult{}, err
		}
		if r, ok := decodeWait(uint32(ws)); ok {
			return r, nil
		}
	}
}

// decodeWait decodes a wait status from its bits (the same on darwin and
// linux): low 7 bits 0 is an exit, 0x7f a stop, anything else death by
// that signal. syscall.WaitStatus.Stopped cannot be used: on darwin it
// reports a SIGSTOP stop as "continued", and SIGSTOP is how a PTY child,
// whose orphaned process group ignores SIGTSTP, gets stopped. ok is false
// for a continue report (linux 0xffff), which callers wait past.
func decodeWait(w uint32) (waitResult, bool) {
	low := w & 0x7f
	high := (w >> 8) & 0xff
	switch {
	case low == 0:
		return waitResult{exited: true, code: int(high)}, true
	case low == 0x7f:
		if high == 0xff {
			return waitResult{}, false
		}
		return waitResult{stopped: true, stopSign: syscall.Signal(high)}, true
	}
	return waitResult{exited: true, code: 128 + int(low)}, true
}

// killGroup signals the process group pgid. The wrapper only ever passes
// the pid of a child it started with Setsid, which leads a process group
// in a session of its own (D57).
func killGroup(pgid int, sig syscall.Signal) error {
	if pgid <= 1 {
		return os.ErrInvalid
	}
	return syscall.Kill(-pgid, sig)
}

// stopSelf stops the wrapper the way a shell job is stopped.
func stopSelf() error { return syscall.Kill(syscall.Getpid(), syscall.SIGTSTP) }

// setSession makes cmd the leader of a new session (and process group);
// ctty also makes its stdin the controlling terminal (the PTY child).
func setSession(cmd *exec.Cmd, ctty bool) {
	attrs := cmd.SysProcAttr
	if attrs == nil {
		attrs = &syscall.SysProcAttr{}
	}
	attrs.Setsid = true
	attrs.Setctty = ctty
	attrs.Ctty = 0
	// Incompatible with Setsid: setpgid on a session leader fails, and a
	// new session has no foreground group to join.
	attrs.Setpgid = false
	attrs.Pgid = 0
	attrs.Foreground = false
	attrs.Noctty = false
	cmd.SysProcAttr = attrs
}

// exitStatus returns the exit code of a reaped child: its status, or
// 128+signal when a signal killed it (the shell's convention).
func exitStatus(ps *os.ProcessState) int {
	if ps == nil {
		return 1
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		switch {
		case ws.Signaled():
			return 128 + int(ws.Signal())
		case ws.Exited():
			return ws.ExitStatus()
		}
	}
	if c := ps.ExitCode(); c >= 0 {
		return c
	}
	return 1
}

// startErrorCode maps an exec failure to the shell's convention.
func startErrorCode(err error) int {
	var pe *os.PathError
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
		return 127
	case errors.As(err, &pe) && errors.Is(pe.Err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		return 126
	}
	return 1
}
