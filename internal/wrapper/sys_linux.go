package wrapper

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// waitReadable waits up to d for fd to become readable (select(2)).
func waitReadable(fd int, d time.Duration) (bool, error) {
	var set syscall.FdSet
	if !fdSet(&set, fd) {
		return false, errFdRange
	}
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	n, err := syscall.Select(fd+1, &set, nil, nil, &tv)
	if err != nil {
		if err == syscall.EINTR {
			return false, nil
		}
		return false, err
	}
	return n > 0 && fdIsSet(&set, fd), nil
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

// ttyName returns the device path of the terminal open on fd ("" if none).
func ttyName(fd int) string {
	name, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	return name
}
