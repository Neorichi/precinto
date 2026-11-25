//go:build failpoints

package live_test

// Fault injection on the lease protocol (docs/TESTPLAN.md §4, run by
// `make test-crash`): errno faults on the lease descriptions, and a wrapper
// SIGKILLed while it takes its leases. The tests are not parallel: failpoint
// hit counters are process-wide.

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx/failpoint"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
)

// An errno while writing a lease description fails the whole Acquire and
// leaves nothing held (the wrapper does not restore without a lease, and a
// sealer is never blocked by a failed launch).
func TestLeaseDescriptionErrnoFailsAcquireCleanly(t *testing.T) {
	failpoint.Reset()
	t.Cleanup(failpoint.Reset)
	dir := t.TempDir()
	keys := []string{"unit-one", "unit-two"}
	for _, spec := range []string{"fsx.write=errno:ENOSPC", "fsx.write=errno:EIO:2", "fsx.fsync=errno:EACCES:2"} {
		failpoint.Reset()
		failpoint.Set(spec)
		h, err := live.Acquire(dir, keys, live.Lease{Proc: platform.ProcID{PID: 1, StartUS: 1}})
		if err == nil || h != nil {
			t.Fatalf("%s: Acquire = %v, %v; want an error", spec, h, err)
		}
		for _, k := range keys {
			if held, _, err := live.Probe(dir, k); held || err != nil {
				t.Fatalf("%s: %s still held after a failed Acquire (%v)", spec, k, err)
			}
		}
	}
	// SetChild fails, but the leases stay held: an error never lowers
	// liveness.
	failpoint.Reset()
	h, err := live.Acquire(dir, keys, live.Lease{Proc: platform.ProcID{PID: 1, StartUS: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	failpoint.Reset() // hit counters restart: the next write fails
	failpoint.Set("fsx.write=errno:ENOSPC")
	if err := h.SetChild(platform.ProcID{PID: 2, StartUS: 2}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("SetChild = %v, want ENOSPC", err)
	}
	for _, k := range keys {
		if held, _, _ := live.Probe(dir, k); !held {
			t.Fatalf("%s released by a failed SetChild", k)
		}
	}
}

// A wrapper SIGKILLed while taking its leases: the kernel releases its
// flocks, a sealer probing afterwards finds the units unleased, and the
// next wrapper drops the crashed holder's descriptions.
func TestCrashedLeaseHolderReleasesItsLeases(t *testing.T) {
	failpoint.Reset()
	t.Cleanup(failpoint.Reset)
	dir := t.TempDir()
	keys := []string{"unit-one", "unit-two", "unit-three"}
	args := []string{"-test.run=^TestHelperLeaseHolder$", "--", "hold", dir}
	args = append(args, keys...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = []string{} // the helper needs no environment
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifeline.Close() // the helper's lifeline: closed when this test ends
	cmd.Stdin = life
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	life.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("helper exited normally (%v); want SIGKILL at the failpoint", err)
		}
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("helper exit %v; want SIGKILL", err)
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill() // our own child
		<-done
		t.Fatal("the helper did not crash at the failpoint")
	}
	// The helper took the first lease and died while describing the second.
	if _, err := os.Lstat(filepath.Join(dir, "unit-one.lease")); err != nil {
		t.Fatalf("the helper never took its first lease: %v", err)
	}
	clock := fakeplatform.NewClock(time.Now())
	e := &live.Engine{Procs: fakeplatform.NewProcs(), Clock: clock, LeasesDir: dir, Observer: live.NewObserver(clock), Quiet: time.Second}
	for _, k := range keys {
		if held, _, err := live.Probe(dir, k); held || err != nil {
			t.Fatalf("%s held after its holder was killed: %v", k, err)
		}
		v, err := e.Decide(context.Background(), live.Subject{Key: k, WriterExited: true}, nil)
		if err != nil || v.Live {
			t.Fatalf("%s: %+v %v", k, v, err)
		}
	}
	h, err := live.Acquire(dir, keys, live.Lease{Proc: platform.ProcID{PID: 3, StartUS: 3}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	for _, k := range keys {
		_, leases, _ := live.Probe(dir, k)
		if len(leases) != 1 || leases[0].Proc.PID != 3 {
			t.Fatalf("%s: descriptions %+v, want only the new holder", k, leases)
		}
	}
}

// TestHelperLeaseHolder is the crashing wrapper of the test above; it does
// nothing unless run as `… -- hold <dir> <keys…>`.
func TestHelperLeaseHolder(t *testing.T) {
	args := flag.Args()
	if len(args) < 3 || args[0] != "hold" {
		t.Skip("helper process only")
	}
	// Exits when its lifeline (stdin) closes and after two minutes in any
	// case (TESTPLAN §1.8).
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(70)
	}()
	time.AfterFunc(2*time.Minute, func() { os.Exit(71) })
	failpoint.Reset()
	failpoint.Set("fsx.write:2") // SIGKILL while describing the second lease
	_, err := live.Acquire(args[1], args[2:], live.Lease{Proc: platform.ProcID{PID: os.Getpid(), StartUS: 1}})
	t.Fatalf("Acquire returned (%v) instead of crashing at the failpoint", err)
}
