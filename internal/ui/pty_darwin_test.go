package ui_test

import (
	"syscall"
	"unsafe"
)

// echoFlag is ECHO in termios c_lflag.
const echoFlag = syscall.ECHO

// pendinFlag is PENDIN in c_lflag: a kernel state bit ("retype pending
// input") the BSD tty driver sets by itself whenever ICANON is turned back
// on, so it is not part of the mode a prompt must restore.
const pendinFlag = syscall.PENDIN

// openPTYFds opens a pseudo-terminal master (posix_openpt, grantpt,
// unlockpt, ptsname) with the standard library only.
func openPTYFds() (master int, slave string, err error) {
	m, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, req := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), req, 0); e != 0 {
			_ = syscall.Close(m)
			return -1, "", e
		}
	}
	name := make([]byte, 128) // TIOCPTYGNAME writes a NUL-terminated path
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		_ = syscall.Close(m)
		return -1, "", e
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	return m, string(name[:n]), nil
}

// getTermios returns the terminal attributes of fd (tcgetattr).
func getTermios(fd int) (syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGETA, uintptr(unsafe.Pointer(&t))); e != 0 {
		return t, e
	}
	return t, nil
}

// setTermios sets the terminal attributes of fd (tcsetattr TCSANOW).
func setTermios(fd int, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSETA, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}
