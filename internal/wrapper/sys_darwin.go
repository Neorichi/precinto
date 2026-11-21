package wrapper

import (
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// waitReadable waits up to d for fd to become readable. select(2) works on
// terminal and PTY devices on darwin, where poll(2) and kqueue do not.
func waitReadable(fd int, d time.Duration) (bool, error) {
	var set syscall.FdSet
	if !fdSet(&set, fd) {
		return false, errFdRange
	}
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	if err := syscall.Select(fd+1, &set, nil, nil, &tv); err != nil {
		if err == syscall.EINTR {
			return false, nil
		}
		return false, err
	}
	return fdIsSet(&set, fd), nil
}

func fdSet(set *syscall.FdSet, fd int) bool {
	bits := 8 * int(unsafe.Sizeof(set.Bits[0]))
	if fd < 0 || fd >= len(set.Bits)*bits {
		return false
	}
	set.Bits[fd/bits] |= 1 << (uint(fd) % uint(bits))
	return true
}

func fdIsSet(set *syscall.FdSet, fd int) bool {
	bits := 8 * int(unsafe.Sizeof(set.Bits[0]))
	return set.Bits[fd/bits]&(1<<(uint(fd)%uint(bits))) != 0
}

// fGetPath is darwin's F_GETPATH fcntl command.
const fGetPath = 50

// ttyName returns the device path of the terminal open on fd ("" if none).
func ttyName(fd int) string {
	var buf [1024]byte // MAXPATHLEN
	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), fGetPath, uintptr(unsafe.Pointer(&buf[0]))); e != 0 {
		return ""
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	name := string(buf[:n])
	if !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	return name
}
