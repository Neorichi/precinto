//go:build darwin || linux

package ui

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

// errFdRange: select(2) cannot watch descriptors at or above FD_SETSIZE.
var errFdRange = errors.New("terminal descriptor beyond FD_SETSIZE")

// watchedSignals are the signals a running prompt handles: SIGINT, SIGTERM,
// SIGHUP and SIGQUIT cancel it once the terminal mode is restored, and
// SIGCONT re-applies raw mode. Signals the process ignores stay ignored.
func watchedSignals() []os.Signal {
	var out []os.Signal
	for _, s := range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		if !signal.Ignored(s) {
			out = append(out, s)
		}
	}
	return append(out, syscall.SIGCONT)
}

// isContinueSignal reports whether sig is SIGCONT (not a cancellation).
func isContinueSignal(sig os.Signal) bool { return sig == syscall.SIGCONT }

// openTerminalFile opens a terminal device read-write without making it the
// controlling terminal. The descriptor stays blocking (os.NewFile does not
// register it with the poller): prompts wait for input with select(2), which
// works on terminals on darwin and linux alike.
func openTerminalFile(path string) (*os.File, error) {
	for {
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}

// hasControllingTerminal reports whether the process has a controlling
// terminal: opening /dev/tty fails (ENXIO) without one (setsid, double fork,
// hooks; D59).
func hasControllingTerminal() bool {
	for {
		fd, err := syscall.Open(devTTY, syscall.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return false
		}
		_ = syscall.Close(fd)
		return true
	}
}

// waitInput waits up to timeout for input on t.in. An interrupted wait
// reports no input so the caller re-checks signals.
func (t *TTY) waitInput(timeout time.Duration) (bool, error) {
	var ready bool
	var serr error
	if err := control(t.in, func(fd int) { ready, serr = selectRead(fd, timeout) }); err != nil {
		return false, err
	}
	if serr == syscall.EINTR {
		return false, nil
	}
	return ready, serr
}

// readInput reads pending input into p. eof reports a terminal that hung
// up; n == 0 with a nil error means the read should simply be retried.
func (t *TTY) readInput(p []byte) (n int, eof bool, err error) {
	rc, err := t.in.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var rerr error
	if err := rc.Read(func(fd uintptr) bool {
		n, rerr = syscall.Read(int(fd), p)
		return true
	}); err != nil {
		return 0, false, err
	}
	switch {
	case rerr == syscall.EINTR || rerr == syscall.EAGAIN:
		return 0, false, nil
	case rerr != nil:
		return 0, false, rerr
	case n == 0:
		return 0, true, nil
	}
	return n, false, nil
}

// fdSet adds fd to set; false if fd is outside FD_SETSIZE.
func fdSet(set *syscall.FdSet, fd int) bool {
	bits := 8 * int(unsafe.Sizeof(set.Bits[0]))
	if fd < 0 || fd >= len(set.Bits)*bits {
		return false
	}
	set.Bits[fd/bits] |= 1 << (uint(fd) % uint(bits))
	return true
}

// fdIsSet reports whether fd (added with fdSet) is in set.
func fdIsSet(set *syscall.FdSet, fd int) bool {
	bits := 8 * int(unsafe.Sizeof(set.Bits[0]))
	return set.Bits[fd/bits]&(1<<(uint(fd)%uint(bits))) != 0
}
