package sweep

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// childTimeout bounds one child test process: it is killed after it (and
// the test fails) if it has not exited.
const childTimeout = 2 * time.Minute

// lifelineEnv marks a child test process that inherited a lifeline pipe
// as file descriptor 3.
const lifelineEnv = "SWEEP_CHILD_LIFELINE"

// holdLifeline is called first by a child test process: when its parent's
// end of the lifeline closes (the parent test ended or died), the child
// exits at once, so it never outlives the test that started it.
func holdLifeline() {
	if os.Getenv(lifelineEnv) != "1" {
		return
	}
	f := os.NewFile(3, "lifeline")
	go func() {
		_, _ = io.Copy(io.Discard, f)
		os.Exit(9)
	}()
}

// runChild re-runs this test binary as a child of the current test with
// env added, a lifeline on fd 3 and a timeout, and returns its output and
// its wait error (nil when it exited 0). A child still running when the
// timeout ends is killed and fails the test.
func runChild(t *testing.T, env ...string) ([]byte, error) {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close() // the lifeline: closing it ends a child still running
	ctx, cancel := context.WithTimeout(t.Context(), childTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(append(os.Environ(), lifelineEnv+"=1"), env...)
	cmd.ExtraFiles = []*os.File{pr}
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Errorf("child did not finish within %v:\n%s", childTimeout, out)
	}
	return out, err
}

// killedBySIGKILL reports a child that its own crash point killed.
func killedBySIGKILL(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}
