//go:build darwin || linux

package codextest

import (
	"errors"
	"os"
	"syscall"
)

// tryFlock takes an exclusive non-blocking flock(2) on f and reports
// busy=true when another open file description holds it. Rust's
// File::try_lock (and File::lock, which HoldWriterLock emulates by polling)
// are flock(2) on darwin and linux, which is what Codex 0.154 uses for
// thread-writer-locks.
func tryFlock(f *os.File) (busy bool, err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		for {
			serr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(serr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return false, err
	}
	if errors.Is(serr, syscall.EWOULDBLOCK) || errors.Is(serr, syscall.EAGAIN) {
		return true, nil
	}
	return false, serr
}
