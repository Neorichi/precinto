//go:build darwin || linux

package vault

import "syscall"

// pinOpenFlags open a plugin binary for hashing: never through a final
// symlink, and never blocking on a FIFO swapped in after the lstat.
const pinOpenFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
