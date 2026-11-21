//go:build darwin

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// darwin hardening (RLIMIT_CORE, ptrace/dumpable, uid checks) is implemented here by G2.
const hardenImpl = "darwin"

// sysHarden denies debugger attachment (PT_DENY_ATTACH); RLIMIT_CORE and
// the uid check are done by harden.
func sysHarden() error {
	if err := unix.PtraceDenyAttach(); err != nil {
		return fmt.Errorf("platform: deny debugger attach: %w", err)
	}
	return nil
}
