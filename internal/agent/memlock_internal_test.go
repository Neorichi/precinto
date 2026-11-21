//go:build darwin || linux

package agent

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The daemon cannot import x/sys/unix; its RLIMIT_MEMLOCK constant must
// equal the kernel's on every darwin and linux architecture.
func TestRlimitMemlockConstant(t *testing.T) {
	if rlimitMemlock != unix.RLIMIT_MEMLOCK {
		t.Fatalf("rlimitMemlock = %d, want %d", rlimitMemlock, unix.RLIMIT_MEMLOCK)
	}
}
