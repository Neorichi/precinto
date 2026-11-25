//go:build crossgroup && testing

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/testkit"
)

// D157 (G7 + G2 + G3): the wrapper records the session the child's own
// registry entry names (ChildSessions, D107) also after a WSL 2 host
// sleep moved btime forward by 8 hours (bootTimeFn shifted): it compares
// entries with the child's start as measured right after the spawn
// (backend.childStarted), not with one computed from a later btime; and
// it still leaves out an entry written before the child started (a
// reused pid).
func TestCrossChildSessionsAcrossABtimeJump(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only linux derives a process's wall-clock start from btime (D66)")
	}
	h := testkit.NewHome(t)
	eng := &sweepEngine{layout: h.Layout}
	l := &claudetest.Layout{ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp, CacheDir: h.ClaudeCache}
	child := platform.Self()
	started := platform.StartTime(child) // what RecordLaunch measures
	if started.IsZero() {
		t.Fatal("platform.StartTime of the test process is unknown")
	}
	bt := started.UnixMicro() - child.StartUS
	platform.NoteBootTime(h.Layout.RunDir) // the daemon's tick before the sleep
	const sid = "00000000-0000-4000-8000-000000000157"
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: child.PID, SessionID: sid, StartedAt: started, Valid: true})

	const sleep = 8 * time.Hour
	restore := platform.SetBootTimeForTest(func() (int64, error) { return bt + sleep.Microseconds(), nil })
	defer restore()
	ctx := context.Background()
	sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child, started)
	if err != nil || !slices.Equal(sids, []string{sid}) {
		t.Fatalf("after an 8 h btime jump: %v, %v; want [%s]", sids, err, sid)
	}
	// An entry from before the child started is still not the child's.
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: child.PID, SessionID: sid, StartedAt: started.Add(-sleep - time.Hour), Valid: true})
	if sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child, started); err != nil || len(sids) != 0 {
		t.Fatalf("an entry 9 h older than the child: %v, %v", sids, err)
	}
}

// D157: a child started after a WSL 2 host sleep has its start measured
// with the btime of then, not with the earliest btime of the boot, which
// the agent recorded before the sleep and which would put the start hours
// too early: an entry a dead process with the same pid left an hour
// before the child started (OOM-killed Claude, pid reused) is not taken
// for the child's, so its session is never recorded as the child's (its
// owner and folders would stay in the ledger).
func TestCrossChildSessionsOfAChildStartedAfterASleep(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only linux derives a process's wall-clock start from btime (D66)")
	}
	h := testkit.NewHome(t)
	eng := &sweepEngine{layout: h.Layout}
	l := &claudetest.Layout{ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp, CacheDir: h.ClaudeCache}
	child := platform.Self()
	now := platform.StartTime(child)
	if now.IsZero() {
		t.Fatal("platform.StartTime of the test process is unknown")
	}
	bt := now.UnixMicro() - child.StartUS
	// The agent's tick before an 8 h sleep recorded the btime of then,
	// 8 h earlier than the one the child started under: the run
	// directory's record, as NoteBootTime writes it (calling NoteBootTime
	// or EarliestStartTime here would lower this test binary's own floor
	// for the tests after this one). EarliestStartTime would now put the
	// child's start 8 h early.
	const sleep = 8 * time.Hour
	rec := fmt.Sprintf("%s %d\n", child.BootID, bt-sleep.Microseconds())
	if err := os.WriteFile(filepath.Join(h.Layout.RunDir, "boottime"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &backend{}
	started := b.childStarted(child) // RecordLaunch, right after the spawn
	if !started.Equal(now) {
		t.Fatalf("the child's start %v, want %v", started, now)
	}
	const stale = "00000000-0000-4000-8000-000000000158"
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: child.PID, SessionID: stale, StartedAt: now.Add(-time.Hour), Valid: true})
	ctx := context.Background()
	if sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child, started); err != nil || len(sids) != 0 {
		t.Fatalf("a stale entry of the same pid, an hour before the child: %v, %v; want none", sids, err)
	}
	// The child's own entry is its.
	const own = "00000000-0000-4000-8000-000000000159"
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: child.PID, SessionID: own, StartedAt: now, Valid: true})
	if sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child, started); err != nil || !slices.Equal(sids, []string{own}) {
		t.Fatalf("the child's own entry: %v, %v", sids, err)
	}
}
