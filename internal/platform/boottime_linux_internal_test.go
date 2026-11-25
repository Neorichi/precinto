//go:build linux

package platform

import (
	"os"
	"testing"
	"time"
)

// D157: inside WSL 2 btime jumps forward after the host sleeps. StartTime
// follows it (a later start, never an earlier one); EarliestStartTime keeps
// the btime noted before the jump, in this process and, through the run
// directory, in a process started after it.
func TestEarliestStartTimeAcrossABtimeJump(t *testing.T) {
	resetFloor(t)
	dir := privateRunDir(t)
	self, _, err := sysIdentifyState(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	bt, err := sysBootTimeUS()
	if err != nil {
		t.Fatal(err)
	}
	restore := setBootTime(func() (int64, error) { return bt, nil })
	defer restore()
	before := startTime(self)
	noteBootTime(dir) // the daemon's tick before the sleep

	const sleep = 8 * time.Hour
	setBootTime(func() (int64, error) { return bt + sleep.Microseconds(), nil })
	if got := startTime(self); !got.Equal(before.Add(sleep)) {
		t.Fatalf("StartTime after the jump = %v, want %v", got, before.Add(sleep))
	}
	if got := earliestStartTime(self, dir); !got.Equal(before) {
		t.Fatalf("EarliestStartTime after the jump = %v, want %v", got, before)
	}
	// A process started after the sleep: only the run directory knows.
	resetFloor(t)
	if got := earliestStartTime(self, dir); !got.Equal(before) {
		t.Fatalf("a new process: EarliestStartTime = %v, want %v", got, before)
	}
	resetFloor(t)
	if got := earliestStartTime(self, ""); !got.Equal(before.Add(sleep)) {
		t.Fatalf("a new process without the run directory: %v", got)
	}
	// A liveness query never writes the record (only NoteBootTime does).
	resetFloor(t)
	fresh := privateRunDir(t)
	earliestStartTime(self, fresh)
	if _, err := os.Lstat(fresh + "/" + bootTimeName); err == nil {
		t.Fatal("EarliestStartTime wrote the record")
	}
	// A ProcID of another boot gets the current btime, like StartTime; one
	// without a boot id is wall time.
	other := self
	other.BootID = "00000000-0000-4000-8000-0000000000ff"
	if got, want := earliestStartTime(other, dir), startTime(other); !got.Equal(want) {
		t.Fatalf("another boot: %v, want %v", got, want)
	}
	fake := ProcID{PID: 7, StartUS: 1_700_000_000_000_000}
	if got := earliestStartTime(fake, dir); !got.Equal(time.UnixMicro(fake.StartUS)) {
		t.Fatalf("a fake ProcID: %v", got)
	}
	// Without btime both are unknown.
	setBootTime(func() (int64, error) { return 0, os.ErrNotExist })
	if !earliestStartTime(self, dir).IsZero() || !startTime(self).IsZero() {
		t.Fatal("a start without btime is not the zero time")
	}
	noteBootTime(dir) // nothing to note: no panic, no record change
}
