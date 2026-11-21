//go:build failpoints

package sweep

import "testing"

// runCrashChild re-runs this test binary as the crash child of the current
// test (runChild: lifeline, timeout) and requires it to have been SIGKILLed
// by its own crash point; it returns the child's output.
func runCrashChild(t *testing.T, env ...string) []byte {
	t.Helper()
	out, err := runChild(t, env...)
	if t.Failed() {
		t.FailNow()
	}
	if !killedBySIGKILL(err) {
		t.Fatalf("child status %v, want SIGKILL by its crash point:\n%s", err, out)
	}
	return out
}
