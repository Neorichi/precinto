//go:build crossgroup && testing

package claude_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
)

// d157Child marks the helper run of this test binary: a process started
// after the host slept (a sealing worker), checking the parent's start.
const d157Child = "PRECINTO_TEST_D157_CHILD"

// D157 (G3 + G2): inside WSL 2 btime jumps forward when the Windows host
// sleeps, here by 8 hours (bootTimeFn shifted). A live session's registry
// entry, written before the sleep with the process's real start, stays
// registry evidence (E2) after it: in this process, which noted the
// earlier btime, and in a process started after the sleep, which finds it
// in the run directory where the daemon's tick recorded it. StartTime, the
// strict start of signal decisions, follows the jump.
func TestCrossD157RegistryHoldsAcrossABtimeJump(t *testing.T) {
	if os.Getenv(d157Child) != "" {
		d157ChildRun(t)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("only linux derives a process's wall-clock start from btime (D66)")
	}
	f := newFx(t)
	f.e.Procs = platform.System()
	run := f.h.Layout.RunDir
	self := platform.Self()
	started := platform.StartTime(self)
	if started.IsZero() {
		t.Fatal("platform.StartTime of the test process is unknown")
	}
	bt := started.UnixMicro() - self.StartUS
	platform.NoteBootTime(run) // the daemon's tick before the sleep
	f.session(sid1, f.h.Root, nil)
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: self.PID, SessionID: sid1, StartedAt: started, Valid: true})
	u := sessionUnit(t, f, sid1)

	const sleep = 8 * time.Hour
	shifted := bt + sleep.Microseconds()
	restore := platform.SetBootTimeForTest(func() (int64, error) { return shifted, nil })
	defer restore()
	if got := platform.StartTime(self); !got.Equal(started.Add(sleep)) {
		t.Fatalf("StartTime after the jump = %v, want %v (the strict start follows btime)", got, started.Add(sleep))
	}
	evs, err := f.a.Probe(context.Background(), f.e, u)
	if err != nil {
		t.Fatal(err)
	}
	held := false
	for _, ev := range evs {
		held = held || (ev.Reason == live.ReasonRegistry && ev.Proc == self)
	}
	if !held {
		t.Fatalf("after an 8 h btime jump the live session lost its registry evidence: %+v", evs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrossD157RegistryHoldsAcrossABtimeJump$", "-test.count=1")
	cmd.Env = []string{
		"PATH=/usr/bin:/bin", d157Child + "=1",
		"D157_RUN=" + run, "D157_PID=" + strconv.Itoa(self.PID),
		"D157_BTIME=" + strconv.FormatInt(shifted, 10), "D157_START=" + strconv.FormatInt(started.UnixMicro(), 10),
	}
	cmd.WaitDelay = 10 * time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("a process started after the sleep: %v\n%s", err, out)
	}
}

// d157ChildRun is the process started after the sleep: its own btime
// reading is the shifted one; the run directory gives it the earlier btime.
func d157ChildRun(t *testing.T) {
	num := func(k string) int64 {
		v, err := strconv.ParseInt(os.Getenv(k), 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return v
	}
	shifted, start := num("D157_BTIME"), num("D157_START")
	platform.SetBootTimeForTest(func() (int64, error) { return shifted, nil })
	id, err := platform.Identify(int(num("D157_PID")))
	if err != nil {
		t.Fatal(err)
	}
	if got := platform.StartTime(id).UnixMicro(); got == start {
		t.Fatalf("the shifted btime did not apply (start %d)", got)
	}
	if got := platform.EarliestStartTime(id, os.Getenv("D157_RUN")).UnixMicro(); got != start {
		t.Fatalf("EarliestStartTime in a new process = %d, want the recorded start %d", got, start)
	}
}
