//go:build darwin || linux

package codextest_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness/codex/codextest"
)

const probeArg = "codextest-flock-probe"

// probe reports whether another open file description holds a flock on
// path (the probe's own short-lived lock is released at once).
func probe(t *testing.T, path string) (held bool) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false
	case errors.Is(err, syscall.EWOULDBLOCK):
		return true
	}
	t.Fatalf("flock %s: %v", path, err)
	return false
}

// probeFromAnotherProcess runs this test binary as TestHelperFlockProbe and
// returns "held" or "free" for path, as a second Codex process (or lsof)
// would see it.
func probeFromAnotherProcess(t *testing.T, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperFlockProbe$", "-test.count=1", "--", probeArg, path)
	cmd.Env = []string{} // the helper needs no environment
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe process: %v\n%s", err, out)
	}
	for _, state := range []string{"held", "free"} {
		if bytes.Contains(out, []byte("PROBE="+state+"\n")) {
			return state
		}
	}
	t.Fatalf("probe process output:\n%s", out)
	return ""
}

// TestHelperFlockProbe is the helper process of probeFromAnotherProcess; it
// skips unless invoked with its arguments.
func TestHelperFlockProbe(t *testing.T) {
	args := flag.Args()
	if len(args) != 2 || args[0] != probeArg {
		t.Skip("helper process for the writer-lock tests")
	}
	f, err := os.OpenFile(args[1], os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("PROBE=error %v\n", err)
		return
	}
	defer f.Close()
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); {
	case err == nil:
		fmt.Println("PROBE=free")
	case errors.Is(err, syscall.EWOULDBLOCK):
		fmt.Println("PROBE=held")
	default:
		fmt.Printf("PROBE=error %v\n", err)
	}
}

func TestWithLocksAreUnheld(t *testing.T) {
	t.Parallel()
	h := codextest.New(t, t.TempDir(), codextest.Options{Rollouts: 2, WithLocks: true})
	locks, _ := filepath.Glob(filepath.Join(h.Dir, "thread-writer-locks", "*.lock")) // includes .coordination.lock
	for _, p := range locks {
		if probe(t, p) {
			t.Errorf("%s is held", p)
		}
	}
	if len(locks) != 3 {
		t.Fatalf("lock files %v, want two thread locks and .coordination.lock", locks)
	}
}

func TestHoldWriterLockFlocksLikeCodex(t *testing.T) {
	t.Parallel()
	h := codextest.New(t, t.TempDir(), codextest.Options{Rollouts: 2, Marker: marker, WithLocks: true})
	rolls := h.Rollouts(t)
	id, other := threadOf(t, rolls[1]), threadOf(t, rolls[0])
	dir := filepath.Join(h.Dir, "thread-writer-locks")
	lock := filepath.Join(dir, id+".lock")
	coord := filepath.Join(dir, ".coordination.lock")
	// Codex opens the lock read/write/create without truncating it.
	if err := os.WriteFile(lock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	release := h.HoldWriterLock(t, id)
	if fi, err := os.Stat(lock); err != nil || fi.Size() != 1 {
		t.Fatalf("lock file after acquire: %v %v (truncated?)", fi, err)
	}
	if !probe(t, lock) {
		t.Fatal("the writer lock is not held in this process's view")
	}
	if got := probeFromAnotherProcess(t, lock); got != "held" {
		t.Fatalf("another process sees the writer lock %s", got)
	}
	// The coordination lock is held only during acquire and release.
	if probe(t, coord) || probeFromAnotherProcess(t, coord) != "free" {
		t.Fatal("the coordination lock stayed held")
	}

	// A second writer for the same thread is Codex's conflict.
	msg := expectFatal(t, func(tb testing.TB) { h.HoldWriterLock(tb, id) })
	if !strings.Contains(msg, "active writer") {
		t.Fatalf("conflict message %q", msg)
	}
	if probe(t, coord) || !probe(t, lock) {
		t.Fatal("a failed acquire leaked the coordination lock or dropped the writer lock")
	}
	// Other threads lock independently.
	releaseOther := h.HoldWriterLock(t, other)

	// Release closes the descriptor and removes the file, as Codex's guard
	// drop does; it is idempotent; other lock files are left alone (no
	// stale-lock sweep).
	release()
	release()
	if _, err := os.Lstat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock file after release: %v", err)
	}
	if !probe(t, filepath.Join(dir, other+".lock")) {
		t.Fatal("releasing one thread released another")
	}
	releaseOther()
	if _, err := os.Lstat(coord); err != nil {
		t.Fatalf("the coordination lock file must survive: %v", err)
	}

	// The thread can be locked again; a test that forgets to release is
	// cleaned up when it ends.
	t.Run("cleanup", func(t *testing.T) {
		h.HoldWriterLock(t, id)
		if !probe(t, lock) {
			t.Fatal("not held")
		}
	})
	if _, err := os.Lstat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock file after the subtest's cleanup: %v", err)
	}
}

func TestHoldWriterLockCreatesTheLockDirectory(t *testing.T) {
	t.Parallel()
	h := codextest.New(t, t.TempDir(), codextest.Options{Rollouts: 1})
	if _, err := os.Lstat(filepath.Join(h.Dir, "thread-writer-locks")); !os.IsNotExist(err) {
		t.Fatalf("WithLocks=false created thread-writer-locks: %v", err)
	}
	id := threadOf(t, h.Rollouts(t)[0])
	release := h.HoldWriterLock(t, id)
	defer release()
	if !probe(t, filepath.Join(h.Dir, "thread-writer-locks", id+".lock")) {
		t.Fatal("not held")
	}
	if fi, err := os.Stat(filepath.Join(h.Dir, "thread-writer-locks", ".coordination.lock")); err != nil || fi.Size() != 0 {
		t.Fatalf("coordination lock: %v %v", fi, err)
	}
}

func TestHoldWriterLockRejectsBadInput(t *testing.T) {
	t.Parallel()
	h := codextest.New(t, t.TempDir(), codextest.Options{})
	for _, id := range []string{"", "not-a-uuid", "../0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/x"} {
		expectFatal(t, func(tb testing.TB) { h.HoldWriterLock(tb, id) })
	}
	expectFatal(t, func(tb testing.TB) { (*codextest.Home)(nil).HoldWriterLock(tb, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b") })
	expectFatal(t, func(tb testing.TB) {
		(&codextest.Home{Dir: "relative"}).HoldWriterLock(tb, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
	})
	if _, err := os.Lstat(filepath.Join(h.Dir, "thread-writer-locks")); !os.IsNotExist(err) {
		t.Fatalf("a rejected id created thread-writer-locks: %v", err)
	}
}
