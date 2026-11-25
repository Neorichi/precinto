//go:build darwin || linux

package ipc

import (
	"io/fs"
	"os"
	"syscall"
)

func ownedByMe(st fs.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == os.Getuid()
}
