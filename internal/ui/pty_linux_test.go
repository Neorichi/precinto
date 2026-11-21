package ui_test

import (
	"strconv"
	"syscall"
	"unsafe"
)

// echoFlag is ECHO in termios c_lflag (the standard library does not define
// the termios flags on every linux architecture).
const echoFlag = 0x8

// pendinFlag is PENDIN in c_lflag, a state bit rather than a mode.
const pendinFlag = 0x4000

// openPTYFds opens a pseudo-terminal master (posix_openpt, unlockpt,
// ptsname) with the standard library only.
func openPTYFds() (master int, slave string, err error) {
	m, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	unlock := new(int32)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(unlock))); e != 0 {
		_ = syscall.Close(m)
		return -1, "", e
	}
	n := new(uint32)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCGPTN, uintptr(unsafe.Pointer(n))); e != 0 {
		_ = syscall.Close(m)
		return -1, "", e
	}
	return m, "/dev/pts/" + strconv.Itoa(int(*n)), nil
}

// getTermios returns the terminal attributes of fd (tcgetattr).
func getTermios(fd int) (syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&t))); e != 0 {
		return t, e
	}
	return t, nil
}

// setTermios sets the terminal attributes of fd (tcsetattr TCSANOW).
func setTermios(fd int, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}
