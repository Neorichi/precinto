package codextest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Codex 0.154 thread-store/src/local/writer_lock.rs.
const (
	lockDirName      = "thread-writer-locks"
	coordinationName = ".coordination.lock"
	coordinationWait = 10 * time.Second // Codex blocks in File::lock; a test must not hang forever
	coordinationPoll = 2 * time.Millisecond
)

// acquireCoordination takes the exclusive flock on
// thread-writer-locks/.coordination.lock (opened read/write/create, never
// truncated), polling until coordinationWait elapses.
func acquireCoordination(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(coordinationWait)
	for {
		busy, err := tryFlock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if !busy {
			return f, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("%s stayed locked for %s", path, coordinationWait)
		}
		time.Sleep(coordinationPoll)
	}
}

// holdWriterLock acquires thread-writer-locks/<id>.lock the way Codex's
// WriterLockCoordinator::acquire does: under the coordination lock, open
// <id>.lock read/write/create without truncation and take a non-blocking
// exclusive flock(2) (a held lock is Codex's "thread already has an active
// writer" conflict, here a test failure); then drop the coordination lock.
// The release function mirrors WriterLockGuard::drop: under the
// coordination lock, close the descriptor (releasing the flock) and remove
// the lock file; if coordination fails the file is kept, as Codex does.
// Codex's once-per-process sweep of stale unheld lock files is not
// emulated: it would delete fixture files a test created on purpose
// (Options.WithLocks).
func holdWriterLock(t testing.TB, h *Home, id string) (release func()) {
	t.Helper()
	if h == nil {
		t.Fatalf("codextest: nil *Home")
	}
	home := homeDir(t, h.Dir)
	if !isUUID(id) {
		t.Fatalf("codextest: HoldWriterLock needs a thread id (UUID), got %q", id)
	}
	dir := filepath.Join(home, lockDirName)
	mkdirs(t, home, dir, dirPerm)
	coordPath := filepath.Join(dir, coordinationName)
	path := filepath.Join(dir, id+".lock")
	checkTarget(t, home, coordPath)
	checkTarget(t, home, path)

	coord, err := acquireCoordination(coordPath)
	if err != nil {
		t.Fatalf("codextest: coordination lock: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		coord.Close()
		t.Fatalf("codextest: open %s: %v", path, err)
	}
	busy, err := tryFlock(f)
	if err != nil || busy {
		f.Close()
		coord.Close()
		if busy {
			t.Fatalf("codextest: thread %s already has an active writer (%s is locked)", id, path)
		}
		t.Fatalf("codextest: flock %s: %v", path, err)
	}
	if err := coord.Close(); err != nil {
		f.Close()
		t.Fatalf("codextest: release coordination lock: %v", err)
	}

	var once sync.Once
	release = func() {
		once.Do(func() {
			c, cerr := acquireCoordination(coordPath)
			f.Close()
			if cerr != nil {
				return
			}
			defer c.Close()
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("codextest: remove %s: %v", path, err)
			}
		})
	}
	t.Cleanup(release)
	return release
}
