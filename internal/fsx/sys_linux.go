//go:build linux

package fsx

import (
	"os"

	"golang.org/x/sys/unix"
)

// linux implementation notes (G1): renameat2(RENAME_NOREPLACE) for NoReplace,
// openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) when available, fsync for
// FullSync.
const osName = "linux"

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
