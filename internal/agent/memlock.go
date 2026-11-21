//go:build darwin || linux

package agent

import (
	"fmt"
	"syscall"
)

// raiseMemlock raises RLIMIT_MEMLOCK's soft limit to its hard limit
// (CC-17): every identity and released file key lives in a memguard locked
// buffer, and the default soft limit on linux (often 64 KiB or 8 MiB) is
// far below what a keys request of ipc.MaxKeysPerRequest capsules needs.
// Raising the soft limit up to the hard one needs no privilege.
func raiseMemlock() error {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(rlimitMemlock, &r); err != nil {
		return fmt.Errorf("agent: read RLIMIT_MEMLOCK: %w", err)
	}
	if r.Cur >= r.Max {
		return nil
	}
	r.Cur = r.Max
	if err := syscall.Setrlimit(rlimitMemlock, &r); err != nil {
		return fmt.Errorf("agent: raise RLIMIT_MEMLOCK: %w", err)
	}
	return nil
}
