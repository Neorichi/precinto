package fsx_test

import "golang.org/x/sys/unix"

// swapPaths atomically exchanges two directory entries (RENAME_EXCHANGE).
func swapPaths(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}
