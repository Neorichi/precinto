//go:build darwin

package fsx

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// darwin implementation notes (G1): renameatx_np(RENAME_EXCL) for NoReplace,
// fcntl(F_FULLFSYNC) for FullSync, O_NOFOLLOW_ANY where available.
const osName = "darwin"

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
