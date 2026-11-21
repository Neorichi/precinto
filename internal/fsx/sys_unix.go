//go:build darwin || linux

package fsx

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Open flags shared by darwin and linux.
const (
	oNoFollow = unix.O_NOFOLLOW
	oNonblock = unix.O_NONBLOCK
)

func lstatPath(path string) (Stat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return Stat{}, &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	return statFrom(&st), nil
}

func fstatFile(f *os.File) (Stat, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return Stat{}, err
	}
	var st unix.Stat_t
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.Fstat(int(fd), &st) }); err != nil {
		return Stat{}, err
	}
	if serr != nil {
		return Stat{}, &os.PathError{Op: "fstat", Path: f.Name(), Err: serr}
	}
	return statFrom(&st), nil
}

// openDirNoFollow opens a directory for fsync without following a final
// symlink.
func openDirNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
}

func flockNB(f *os.File, shared bool) error {
	how := unix.LOCK_EX | unix.LOCK_NB
	if shared {
		how = unix.LOCK_SH | unix.LOCK_NB
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		for {
			serr = unix.Flock(int(fd), how)
			if !errors.Is(serr, unix.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	if errors.Is(serr, unix.EWOULDBLOCK) || errors.Is(serr, unix.EAGAIN) {
		return ErrLocked
	}
	return serr
}

func unlockFile(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.Flock(int(fd), unix.LOCK_UN) }); err != nil {
		return err
	}
	return serr
}
