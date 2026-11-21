package ui

import (
	"syscall"
	"time"
)

// selectRead waits up to timeout for fd to become readable (select(2):
// unlike poll(2), it works on terminal devices on darwin).
func selectRead(fd int, timeout time.Duration) (bool, error) {
	var set syscall.FdSet
	if !fdSet(&set, fd) {
		return false, errFdRange
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.Select(fd+1, &set, nil, nil, &tv); err != nil {
		return false, err
	}
	return fdIsSet(&set, fd), nil
}
