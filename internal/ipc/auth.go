package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/precinto/precinto/internal/platform"
)

// errNotExist reports a missing run directory or socket (no daemon).
var errNotExist = errors.New("ipc: not found")

// checkPrivateDir requires path to be a directory (not a symlink) owned by
// the current uid with no group/other permission bits: the D6 rule for the
// socket directory. It is the same rule as fsx.CheckPrivateDir, kept local
// so the protocol does not depend on the rest of fsx.
func checkPrivateDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errNotExist
		}
		return fmt.Errorf("ipc: run directory: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("ipc: run directory is not a plain directory")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ipc: run directory is accessible to other users")
	}
	if !ownedByMe(st) {
		return fmt.Errorf("ipc: run directory is owned by another user")
	}
	return nil
}

// checkSocket requires path to be a socket owned by the current uid.
func checkSocket(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errNotExist
		}
		return fmt.Errorf("ipc: socket: %w", err)
	}
	if st.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("ipc: socket path is not a socket")
	}
	if !ownedByMe(st) {
		return fmt.Errorf("ipc: socket is owned by another user")
	}
	return nil
}

func ownedByMe(st fs.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == os.Getuid()
}

// sameExe reports whether pid runs this binary (D6), the daemon's check of
// a client. Any error counts as "not the same", except where
// sameExeFallback applies.
func sameExe(pid int) bool {
	same, err := platform.SameExecutable(pid)
	if err == nil {
		return same
	}
	if errors.Is(err, fs.ErrPermission) {
		return sameExeFallback(pid)
	}
	return false
}

// serverTrusted is the client's check of the daemon at pid (D6): the same
// executable file, or, when its executable cannot be read (a hardened
// daemon on linux), the D65 facts: it holds lockPath (run/agent.lock) and
// has our kernel name (daemonFallback). Anything else is refused before
// the client sends a byte.
func serverTrusted(pid int, lockPath string) bool {
	same, err := platform.SameExecutable(pid)
	if err == nil {
		return same
	}
	if errors.Is(err, fs.ErrPermission) {
		return daemonFallback(pid, lockPath)
	}
	return false
}
