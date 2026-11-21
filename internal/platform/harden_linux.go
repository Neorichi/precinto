//go:build linux

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// linux hardening (RLIMIT_CORE, ptrace/dumpable, uid checks) is implemented here by G2.
const hardenImpl = "linux"

// sysHarden makes the process non-dumpable (no core dumps, no same-uid
// ptrace or /proc/<pid>/mem access); RLIMIT_CORE and the uid check are done
// by harden.
func sysHarden() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("platform: make the process non-dumpable: %w", err)
	}
	return nil
}
