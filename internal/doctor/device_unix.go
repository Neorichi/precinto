//go:build darwin || linux

package doctor

import (
	"errors"
	"os"
	"syscall"
)

// deviceOf returns the device number of the file system holding path
// (following symlinks, as fsx does).
func deviceOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("doctor: no device number")
	}
	return uint64(st.Dev), nil // int32 on darwin, uint64 on linux
}
