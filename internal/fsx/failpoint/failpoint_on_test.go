//go:build failpoints

package failpoint_test

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

func TestErrnoAtNthHit(t *testing.T) {
	defer failpoint.Reset()
	failpoint.Set("fsx.write=errno:ENOSPC:2, fsx.fsync=errno:EIO")
	if err := failpoint.Hit("fsx.write"); err != nil {
		t.Fatalf("first hit: %v", err)
	}
	if err := failpoint.Hit("fsx.write"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("second hit: %v, want ENOSPC", err)
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		t.Fatalf("third hit: %v", err)
	}
	if err := failpoint.Hit("fsx.fsync"); !errors.Is(err, syscall.EIO) {
		t.Fatalf("fsync: %v", err)
	}
	if got := failpoint.Hits("fsx.write"); got != 3 {
		t.Fatalf("Hits = %d", got)
	}
	failpoint.Reset()
	if failpoint.Hits("fsx.write") != 0 || failpoint.Hit("fsx.fsync") != nil {
		t.Fatal("Reset did not disarm")
	}
}

func TestBadSpecPanics(t *testing.T) {
	for _, spec := range []string{"x=errno:ENOPE", "x:0", "x=oops", "=errno:EIO"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Set(%q) did not panic", spec)
				}
			}()
			failpoint.Set(spec)
		}()
	}
	failpoint.Reset()
}

// TestCrashKillsTheProcess re-runs this test binary as a child that arms a
// crash point and hits it; the child must die by SIGKILL.
func TestCrashKillsTheProcess(t *testing.T) {
	if os.Getenv("FAILPOINT_CHILD") == "1" {
		failpoint.Set("seal.committed")
		_ = failpoint.Hit("seal.committed")
		os.Exit(0) // not reached
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCrashKillsTheProcess")
	cmd.Env = append(os.Environ(), "FAILPOINT_CHILD=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child status %v, want SIGKILL", ee)
	}
}
