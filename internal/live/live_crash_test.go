package live_test

// Crash-matrix rows owned by G3 (docs/TESTPLAN.md §4): LIVE-1–LIVE-9 and
// CODX-6, with fakeplatform processes and clocks and real files. LIVE-4
// (zombie child, with G2's WaitExit) and LIVE-10 (Codex pid by ancestry,
// G5+G2) are covered here only for the liveness side. They run in
// `make test` and `make test-crash`; the fault-injection rows that need
// -tags failpoints are in live_failpoint_crash_test.go.

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// LIVE-6: stability is measured on the monotonic clock.
func TestLIVE6WallJumpDoesNotMakeAUnitStable(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-wall", Paths: []string{r.file("a.jsonl", "x\n")}}
	r.decide(s)
	r.clock.StepWall(time.Hour)
	if v := r.decide(s); !v.Live {
		t.Fatalf("wall +1h made the unit stable: %+v", v)
	}
	r.clock.Sleep(time.Hour) // machine sleep: wall moves, monotonic does not
	if v := r.decide(s); !v.Live {
		t.Fatalf("sleep made the unit stable: %+v", v)
	}
	r.clock.Advance(quiet)
	if v := r.decide(s); v.Live {
		t.Fatalf("not stable after a monotonic quiet window: %+v", v)
	}
}

// LIVE-1: the registry is gone and an end record was written, but the
// ledger process is alive: live until it exits (R8).
func TestLIVE1LedgerProcessKeepsLiveAfterEnd(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := proc(4242, 1_700_000_000_000_000)
	r.procs.Add(p)
	s := live.Subject{Key: "unit-ledger", Paths: []string{r.file("a.jsonl", "x\n")}, Procs: []platform.ProcID{p.ID}}
	for i := 0; i < 3; i++ {
		v := r.decide(s)
		if !v.Live || !reasons(v)[live.ReasonLedgerProc] {
			t.Fatalf("t=%ds: %+v, want ledger-proc", i*65, v)
		}
		r.clock.Advance(65 * time.Second)
	}
	r.procs.Exit(p.ID.PID, false)
	r.clock.Advance(quiet)
	if v := r.decide(s); v.Live {
		t.Fatalf("after exit and a quiet window: %+v", v)
	}
}

// LIVE-3 and LIVE-4: a reused pid or a zombie is not the ledger process.
func TestLIVE3And4PIDReuseAndZombies(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := proc(500, 1_000)
	r.procs.Add(p)
	s := live.Subject{Key: "unit-reuse", Paths: []string{r.file("a.jsonl", "x\n")}, Procs: []platform.ProcID{p.ID}}
	r.settle(s)
	if v := r.decide(s); !reasons(v)[live.ReasonLedgerProc] {
		t.Fatalf("same start time must be live: %+v", v)
	}
	r.procs.Reuse(500, 2_000, "/bin/sh")
	if v := r.decide(s); v.Live {
		t.Fatalf("reused pid kept the unit live: %+v", v)
	}
	z := proc(501, 3_000)
	r.procs.Add(z)
	s.Procs = []platform.ProcID{z.ID}
	if v := r.decide(s); !v.Live {
		t.Fatalf("running process not live")
	}
	r.procs.Exit(501, true)
	if v := r.decide(s); v.Live {
		t.Fatalf("a zombie kept the unit live: %+v", v)
	}
}

// LIVE-2: in the launch window there is no registry, no ledger and the
// mtimes are old, but the wrapper's lease holds the unit.
func TestLIVE2LeaseHoldsTheLaunchWindow(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "0123456789abcdef0123456789abcdef", Paths: []string{r.file("a.jsonl", "x\n")}}
	r.settle(s)
	h, err := live.Acquire(r.engine.LeasesDir, []string{s.Key}, live.Lease{Proc: platform.ProcID{PID: 77, StartUS: 9}, Root: "root-acme"})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, time.Second, 1300 * time.Millisecond} {
		r.clock.Advance(d)
		v := r.decide(s)
		if !v.Live || !reasons(v)[live.ReasonLease] {
			t.Fatalf("+%v: %+v, want lease", d, v)
		}
		if v.Evidence[0].Proc.PID != 77 {
			t.Errorf("lease evidence does not name the wrapper: %+v", v.Evidence[0])
		}
	}
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	if v := r.decide(s); v.Live {
		t.Fatalf("after release: %+v", v)
	}
}

// LIVE-7: a non-current session of a live process (D20) is sealable once
// stable; until then it is live and warm.
func TestLIVE7WarmSessionSealableOnceStable(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.file("old.jsonl", "x\n")
	s := live.Subject{Key: "unit-warm", Paths: []string{p}}
	warm := live.Evidence{Reason: live.ReasonWarm, Detail: "after /clear"}
	v := r.decide(s, warm)
	if !v.Live || !v.Warm || !reasons(v)[live.ReasonWarm] {
		t.Fatalf("warm before stable: %+v", v)
	}
	// A late "continued in" append restarts the window.
	r.clock.Advance(quiet - time.Second)
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte("late\n"))
	f.Close()
	if v := r.decide(s, warm); !v.Live || !v.Warm {
		t.Fatalf("after the late append: %+v", v)
	}
	r.clock.Advance(quiet)
	v = r.decide(s, warm)
	if v.Live || !v.Warm {
		t.Fatalf("warm and stable: %+v, want sealable (not live, warm)", v)
	}
	// Strong evidence still wins over warm.
	if v := r.decide(s, warm, live.Evidence{Reason: live.ReasonRegistry}); !v.Live {
		t.Fatalf("registry evidence ignored for a warm unit: %+v", v)
	}
}

// LIVE-5, LIVE-8, LIVE-9: adapter evidence (registry without startedAt,
// a background job, a half-written registry) is part of the union.
func TestLIVE5And8And9AdapterEvidenceIsPartOfTheUnion(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-adapter", Paths: []string{r.file("a", "x")}}
	r.settle(s)
	for _, ev := range []live.Evidence{
		{Reason: live.ReasonRegistry, Proc: platform.ProcID{PID: 9, StartUS: 1}, Detail: "startedAt missing: mtime fallback"},
		{Reason: live.ReasonJob, Detail: "job running"},
		{Reason: live.ReasonRegistryIO, Detail: "half-written registry"},
		{Reason: live.ReasonOpenFD},
		{Reason: live.ReasonWriterLock},
		{Reason: live.ReasonProcess, Weak: true},
		{Reason: live.ReasonForkParent},
		{Reason: live.ReasonPlanSlug},
		{Reason: live.ReasonUnknown},
	} {
		if v := r.decide(s, ev); !v.Live || !reasons(v)[ev.Reason] {
			t.Errorf("%s: %+v", ev.Reason, v)
		}
	}
}

// CODX-6: the lease file is unlinked and recreated during the probe, or
// the file system does not support flock: both are treated as held.
func TestCODX6ProbeInodeSwapAndUnsupportedLocks(t *testing.T) {
	dir := t.TempDir()
	key := "swap"
	h, err := live.Acquire(dir, []string{key}, live.Lease{})
	if err != nil {
		t.Fatal(err)
	}
	h.Release()
	restore := live.SetProbeHook(func(path string) {
		os.Remove(path)
		os.WriteFile(path, nil, 0o600)
	})
	held, _, err := live.Probe(dir, key)
	restore()
	if !held || err == nil {
		t.Fatalf("inode swap during probe: held %v err %v, want held", held, err)
	}
	if held, _, err := live.Probe(dir, key); held || err != nil {
		t.Fatalf("after the swap settled: %v %v", held, err)
	}
	restore = live.SetTryLock(func(string, bool) (*fsx.Lock, error) {
		return nil, &os.PathError{Op: "flock", Path: "x", Err: syscall.ENOTSUP}
	})
	held, _, err = live.Probe(dir, key)
	_, aerr := live.Acquire(dir, []string{"other"}, live.Lease{})
	restore()
	if !held || !errors.Is(err, syscall.ENOTSUP) {
		t.Fatalf("ENOTSUP: held %v err %v", held, err)
	}
	if aerr == nil {
		t.Fatal("Acquire succeeded without flock support")
	}
	// The engine reads a failed probe as a held lease.
	clock := fakeplatform.NewClock(time.Now())
	e := &live.Engine{Procs: fakeplatform.NewProcs(), Clock: clock, LeasesDir: dir, Observer: live.NewObserver(clock), Quiet: quiet}
	restore = live.SetTryLock(func(string, bool) (*fsx.Lock, error) {
		return nil, &os.PathError{Op: "flock", Path: "x", Err: syscall.ENOTSUP}
	})
	defer restore()
	v, err := e.Decide(context.Background(), live.Subject{Key: key, WriterExited: true}, nil)
	if err != nil || !v.Live || !reasons(v)[live.ReasonLease] {
		t.Fatalf("Decide with ENOTSUP: %+v %v", v, err)
	}
	if ok, err := e.StillQuiet(context.Background(), live.Subject{Key: key}, nil); ok || err == nil {
		t.Fatalf("StillQuiet with ENOTSUP: %v %v", ok, err)
	}
}
