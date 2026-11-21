//go:build linux

package fsx

import (
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// linux implementation notes (G1): renameat2(RENAME_NOREPLACE) for NoReplace,
// openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) when available, fsync for
// FullSync.
const osName = "linux"

// privateGroups enables the D67 user-private group exception (upg.go):
// with umask 002 every directory a harness creates is 0775 and owned by the
// user's private group.
var privateGroups = true

func statFrom(st *unix.Stat_t) Stat {
	return Stat{
		Dev:     uint64(st.Dev),
		Ino:     uint64(st.Ino),
		Mode:    uint32(st.Mode),
		Nlink:   uint32(st.Nlink),
		UID:     uint32(st.Uid),
		Size:    int64(st.Size),
		MtimeNS: st.Mtim.Nano(),
		CtimeNS: st.Ctim.Nano(),
	}
}

func fullSync(f *os.File) error { return f.Sync() }

func fullSyncFD(fd int) error { return retry(func() error { return unix.Fsync(fd) }) }

// renameNoReplace renames with RENAME_NOREPLACE; kernels or file systems
// without it fall back to link + unlink.
func renameNoReplace(ofd int, oname string, nfd int, nname string) error {
	err := retry(func() error { return unix.Renameat2(ofd, oname, nfd, nname, unix.RENAME_NOREPLACE) })
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return linkNoReplace(ofd, oname, nfd, nname)
	}
	return err
}

// isDataless: linux has no file-provider placeholders.
func isDataless(*unix.Stat_t) bool { return false }

// chmodNoFollow changes the mode of name below dirfd without following a
// final symlink. fchmodat(AT_SYMLINK_NOFOLLOW) needs fchmodat2 (linux 6.6);
// older kernels go through an O_PATH descriptor, like glibc.
func chmodNoFollow(dirfd int, name string, mode uint32) error {
	err := retry(func() error { return unix.Fchmodat(dirfd, name, mode, unix.AT_SYMLINK_NOFOLLOW) })
	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.ENOSYS) {
		return err
	}
	fd, err := openat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer closeFD(fd)
	st, err := fstatFD(fd)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	err = retry(func() error {
		return unix.Fchmodat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), mode, 0)
	})
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	// No /proc: open the object itself (never through a symlink).
	rfd, err := openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer closeFD(rfd)
	return retry(func() error { return unix.Fchmod(rfd, mode) })
}

// statfsBytes converts statfs counts (in f_frsize units) to bytes.
func statfsBytes(sf *unix.Statfs_t) (avail, total uint64) {
	unit := uint64(sf.Frsize)
	if unit == 0 {
		unit = uint64(sf.Bsize)
	}
	return sf.Bavail * unit, sf.Blocks * unit
}
