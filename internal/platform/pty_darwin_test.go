package platform_test

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// openPTY opens a pseudo-terminal (posix_openpt, grantpt, unlockpt,
// ptsname) with the standard library; the master is non-blocking so reads
// honour deadlines.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), req, 0); e != 0 {
			syscall.Close(m)
			t.Fatal(e)
		}
	}
	name := make([]byte, 128)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		syscall.Close(m)
		t.Fatal(e)
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	if err := syscall.SetNonblock(m, true); err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(m), "ptmx"), string(name[:n])
}

// hardenedExtra checks OS-specific hardening effects in the child; darwin's
// PT_DENY_ATTACH is not observable without a debugger.
func hardenedExtra() string { return "" }
