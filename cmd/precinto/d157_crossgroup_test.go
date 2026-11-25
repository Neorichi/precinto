//go:build crossgroup && testing

package main

import (
	"context"
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
// sleep moved btime forward by 8 hours (bootTimeFn shifted), and still
// leaves out an entry written before the child started (a reused pid).
func TestCrossChildSessionsAcrossABtimeJump(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only linux derives a process's wall-clock start from btime (D66)")
	}
	h := testkit.NewHome(t)
	eng := &sweepEngine{layout: h.Layout}
	l := &claudetest.Layout{ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp, CacheDir: h.ClaudeCache}
	child := platform.Self()
	started := platform.StartTime(child)
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
	sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child)
	if err != nil || !slices.Equal(sids, []string{sid}) {
		t.Fatalf("after an 8 h btime jump: %v, %v; want [%s]", sids, err, sid)
	}
	// An entry from before the child started is still not the child's.
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: child.PID, SessionID: sid, StartedAt: started.Add(-sleep - time.Hour), Valid: true})
	if sids, err := eng.ChildSessions(ctx, harness.ClaudeCode, h.ClaudeConfig, child); err != nil || len(sids) != 0 {
		t.Fatalf("an entry 9 h older than the child: %v, %v", sids, err)
	}
}
