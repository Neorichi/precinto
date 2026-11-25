package sweep

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

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
func mkfifo(p string) error { return testkit.Mkfifo(p, 0o600) }

// tctx is the context of a run in a test: it ends with the test and after
// 60 s at the latest, so a stuck run fails the test instead of hanging the
// package (FX-G4-02).
func tctx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}
