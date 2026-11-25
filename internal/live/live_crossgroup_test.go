//go:build crossgroup

package live_test

// Cross-group liveness tests: they need G2's real process table
// (platform.System, Identify) and G1's fsx.ProbeHeld, so they compile now
// and run at integration (docs/OWNERSHIP.md §4).

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
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

// leaseChildDir names the lease directory of the holder child process.
const leaseChildDir = "PRECINTO_LIVE_LEASE_CHILD_DIR"

// TestCrossLeaseHolderChild runs only inside a re-executed test binary: it
// holds a lease on "holder" until its stdin (the lifeline) reaches EOF.
func TestCrossLeaseHolderChild(t *testing.T) {
	dir := os.Getenv(leaseChildDir)
	if dir == "" {
		t.Skip("lease holder child only")
	}
	h, err := live.Acquire(dir, []string{"holder"}, live.Lease{Proc: platform.Self(), Root: "root-acme"})
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("ready\n")
	io.Copy(io.Discard, os.Stdin) // the parent closes it, or dies
	h.Release()
}

// CODX-6 (G3 + G1): a lease held by another process through a real flock
// is held for live.Probe (which is fsx.ProbeHeld on the lease file) and
// for fsx.ProbeHeld itself, with the holder's description; once the
// holder exits the lease is free and the file stays.
func TestCrossLeaseHeldByAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrossLeaseHolderChild$", "-test.count=1")
	cmd.Env = []string{leaseChildDir + "=" + dir}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill() // our own child only
			<-done
		}
	})
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, 6)
		_, err := io.ReadFull(stdout, buf)
		if err == nil && string(buf) != "ready\n" {
			err = errors.New("unexpected output from the holder")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("holder: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the lease holder did not start")
	}
	path := filepath.Join(dir, "holder.lease")
	if held, err := fsx.ProbeHeld(path); !held || err != nil {
		t.Fatalf("fsx.ProbeHeld on a lease held by another process: %v %v", held, err)
	}
	held, leases, err := live.Probe(dir, "holder")
	if !held || err != nil || len(leases) != 1 || leases[0].Proc.PID != cmd.Process.Pid || leases[0].Root != "root-acme" {
		t.Fatalf("live.Probe = %v %+v %v, want held by pid %d", held, leases, err, cmd.Process.Pid)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("holder exited with %v", err)
	}
	if held, leases, err := live.Probe(dir, "holder"); held || leases != nil || err != nil {
		t.Fatalf("after the holder exited: %v %+v %v", held, leases, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("lease files are never deleted: %v", err)
	}
}
