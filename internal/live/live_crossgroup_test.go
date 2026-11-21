//go:build crossgroup

package live_test

// Cross-group liveness tests: they need G2's real process table
// (platform.System, Identify) and G1's fsx.ProbeHeld, so they compile now
// and run at integration (docs/OWNERSHIP.md §4).

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// LIVE-4 (G2 + G3): a child that exited but was not reaped is a zombie,
// and a zombie counts as exited: the unit it owned is no longer live.
func TestCrossLIVE4ZombieChildIsNotLive(t *testing.T) {
	procs := platform.System()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cmd.Env = []string{} // explicit: the child needs no environment
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	id, err := platform.Identify(cmd.Process.Pid)
	if err != nil {
		cmd.Wait()
		t.Skipf("the child exited before it could be measured: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for procs.Alive(id) {
		if time.Now().After(deadline) {
			cmd.Wait()
			t.Fatal("the zombie child is still reported alive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	clock := fakeplatform.NewClock(time.Now())
	e := &live.Engine{Procs: procs, Clock: clock, LeasesDir: t.TempDir(), Observer: live.NewObserver(clock), Quiet: time.Second}
	v, err := e.Decide(context.Background(), live.Subject{Key: "zombie-unit", Procs: []platform.ProcID{id}, WriterExited: true}, nil)
	if err != nil || v.Live {
		t.Fatalf("a zombie owner kept the unit live: %+v %v", v, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// A ledger process measured by the real platform keeps its unit live
// while it runs (E1 with ProcID equality, LIVE-1/LIVE-3).
func TestCrossLedgerProcessOfThisTestIsLive(t *testing.T) {
	procs := platform.System()
	self := platform.Self()
	if !procs.Alive(self) {
		t.Fatal("the test process is not alive according to the platform")
	}
	clock := fakeplatform.NewClock(time.Now())
	e := &live.Engine{Procs: procs, Clock: clock, LeasesDir: t.TempDir(), Observer: live.NewObserver(clock), Quiet: time.Second}
	v, err := e.Decide(context.Background(), live.Subject{Key: "self-unit", Procs: []platform.ProcID{self}, WriterExited: true}, nil)
	if err != nil || !v.Live {
		t.Fatalf("the running ledger process was not live evidence: %+v %v", v, err)
	}
	reused := self
	reused.StartUS++
	v, _ = e.Decide(context.Background(), live.Subject{Key: "reused-unit", Procs: []platform.ProcID{reused}, WriterExited: true}, nil)
	if v.Live {
		t.Fatalf("a ProcID with another start time counted as the process (PID reuse): %+v", v)
	}
}

// CODX-6 (G3 + G1): live.Probe and fsx.ProbeHeld agree on lease files.
func TestCrossLeaseProbeAgreesWithFsx(t *testing.T) {
	dir := t.TempDir()
	h, err := live.Acquire(dir, []string{"agree"}, live.Lease{Proc: platform.Self()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agree.lease")
	held, err := fsx.ProbeHeld(path)
	if err != nil || !held {
		t.Fatalf("fsx.ProbeHeld on a held lease: %v %v", held, err)
	}
	if lheld, _, _ := live.Probe(dir, "agree"); !lheld {
		t.Fatal("live.Probe on a held lease")
	}
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	held, err = fsx.ProbeHeld(path)
	if err != nil || held {
		t.Fatalf("fsx.ProbeHeld after release: %v %v", held, err)
	}
	if lheld, _, _ := live.Probe(dir, "agree"); lheld {
		t.Fatal("live.Probe after release")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("lease files are never deleted: %v", err)
	}
}
