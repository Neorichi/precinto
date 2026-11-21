package ui

import (
	"syscall"
	"time"
)

// selectRead waits up to timeout for fd to become readable (select(2)).
func selectRead(fd int, timeout time.Duration) (bool, error) {
	var set syscall.FdSet
	if !fdSet(&set, fd) {
		return false, errFdRange
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	n, err := syscall.Select(fd+1, &set, nil, nil, &tv)
	if err != nil {
		return false, err
	}
	return n > 0 && fdIsSet(&set, fd), nil
}
