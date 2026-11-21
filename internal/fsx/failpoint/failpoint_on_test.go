//go:build failpoints

package failpoint_test

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

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
// The child holds a lifeline: stdin is a pipe whose only write end the
// parent keeps, so the child exits at EOF if the parent goes away first
// (TESTPLAN §1 rule 8); the parent bounds it with a deadline and reaps it.
func TestCrashKillsTheProcess(t *testing.T) {
	if os.Getenv("FAILPOINT_CHILD") == "1" {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			os.Exit(3)
		}()
		failpoint.Set("seal.committed")
		_ = failpoint.Hit("seal.committed")
		os.Exit(0) // not reached
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashKillsTheProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FAILPOINT_CHILD=1")
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifeline.Close()
	cmd.Stdin = life
	err = cmd.Start()
	life.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child status %v, want SIGKILL", ee)
	}
}
