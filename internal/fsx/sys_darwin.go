//go:build darwin

package fsx

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// darwin implementation notes (G1): renameatx_np(RENAME_EXCL) for NoReplace,
// fcntl(F_FULLFSYNC) for FullSync, O_NOFOLLOW_ANY where available.

// privateGroups keeps the D67 user-private group exception (upg.go) off:
// every darwin user's primary group is the shared "staff", so a
// group-writable directory is always unsafe here.
var privateGroups = false

func statFrom(st *unix.Stat_t) Stat {
	return Stat{
		Dev:     uint64(uint32(st.Dev)),
		Ino:     st.Ino,
		Mode:    uint32(st.Mode),
		Nlink:   uint32(st.Nlink),
		UID:     st.Uid,
		Size:    st.Size,
		MtimeNS: st.Mtim.Nano(),
		CtimeNS: st.Ctim.Nano(),
	}
}

// fullSync issues F_FULLFSYNC, falling back to fsync on volumes that do not
// support it (network and some FUSE file systems).
func fullSync(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { _, serr = unix.FcntlInt(fd, unix.F_FULLFSYNC, 0) }); err != nil {
		return err
	}
	if serr == nil {
		return nil
	}
	if errors.Is(serr, unix.ENOTSUP) || errors.Is(serr, unix.EINVAL) || errors.Is(serr, unix.ENOTTY) {
		return f.Sync()
	}
	return &os.PathError{Op: "fcntl F_FULLFSYNC", Path: f.Name(), Err: serr}
}

// fullSyncFD is fullSync for a raw descriptor (directories).
func fullSyncFD(fd int) error {
	err := retry(func() error {
		_, e := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0)
		return e
	})
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTTY) {
		return retry(func() error { return unix.Fsync(fd) })
	}
	return err
}

// renameNoReplace renames with RENAME_EXCL; volumes without it (some
// network file systems) fall back to link + unlink.
func renameNoReplace(ofd int, oname string, nfd int, nname string) error {
	err := retry(func() error { return unix.RenameatxNp(ofd, oname, nfd, nname, unix.RENAME_EXCL) })
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) {
		return linkNoReplace(ofd, oname, nfd, nname)
	}
	return err
}

// isDataless reports an iCloud (or other file provider) placeholder whose
// content is not on disk: reading or listing it would trigger a download,
// so it is treated as inaccessible (SPEC §17).
func isDataless(st *unix.Stat_t) bool { return st.Flags&unix.SF_DATALESS != 0 }

// chmodNoFollow changes the mode of name below dirfd without following a
// final symlink ("." is the directory itself).
func chmodNoFollow(dirfd int, name string, mode uint32) error {
	return retry(func() error { return unix.Fchmodat(dirfd, name, mode, unix.AT_SYMLINK_NOFOLLOW) })
}

// statfsBytes converts statfs counts (in f_bsize units on darwin) to bytes.
func statfsBytes(sf *unix.Statfs_t) (avail, total uint64) {
	bs := uint64(sf.Bsize)
	return sf.Bavail * bs, sf.Blocks * bs
}
