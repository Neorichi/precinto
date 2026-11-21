package fsx_test

import "golang.org/x/sys/unix"

// swapPaths atomically exchanges two directory entries (RENAME_SWAP).
func swapPaths(a, b string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_SWAP)
}
