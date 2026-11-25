//go:build darwin || linux

package testkit

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

// tryLock takes a non-blocking exclusive flock on f (errLocked when another
// open file description holds it).
func tryLock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lerr error
	if err := rc.Control(func(fd uintptr) {
		for {
			lerr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(lerr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	if errors.Is(lerr, syscall.EWOULDBLOCK) || errors.Is(lerr, syscall.EAGAIN) {
		return errLocked
	}
	return lerr
}

// ownedByMe reports whether fi belongs to the effective uid.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

func mkfifo(path string, perm uint32) error { return syscall.Mkfifo(path, perm) }

func newSession() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

func killGroup(pid int) error {
	if pid < 2 {
		return errors.New("testkit: refusing to kill process group " + strconv.Itoa(pid))
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}
