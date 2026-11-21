package sweep

import (
	"fmt"
	"os"
	"syscall"

	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
)

// logEntryFor is a synthetic log entry of a Claude session generation.
func logEntryFor(unit string, gen uint64) capslog.Entry {
	return capslog.Entry{
		Path: fmt.Sprintf("claude-code/%s/g%06d.pcap", unit, gen), SHA256: fmt.Sprintf("%064x", gen),
		HeaderSHA256: fmt.Sprintf("%064x", gen+1), Kind: "claude-session", Harness: "claude-code", Unit: unit,
		VaultID: rootID, RootIDs: []string{rootID}, Gen: gen, Lineage: "fresh", SealedAt: testkit.Epoch,
	}
}

// procInfo is a live process of the fake table.
func procInfo(pid int, start int64) platform.ProcInfo {
	return platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: start}, PPID: 1, UID: os.Getuid(), State: platform.StateRunning}
}

// mkfifo creates a FIFO.
func mkfifo(p string) error { return syscall.Mkfifo(p, 0o600) }
