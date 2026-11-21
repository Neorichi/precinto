package platform_test

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal (posix_openpt, unlockpt, ptsname) with
// the standard library; the master is non-blocking so reads honour
// deadlines.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unlock := int32(0)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		syscall.Close(m)
		t.Fatal(e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(m), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		syscall.Close(m)
		t.Fatal(e)
	}
	if err := syscall.SetNonblock(m, true); err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(m), "ptmx"), "/dev/pts/" + strconv.Itoa(int(n))
}

// hardenedExtra checks that the child became non-dumpable.
func hardenedExtra() string {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || v != 0 {
		return "still dumpable"
	}
	return ""
}
