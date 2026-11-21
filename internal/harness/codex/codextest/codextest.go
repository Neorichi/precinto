package codextest

import (
	"sync"
	"testing"
	"time"
)

// Home is a fake Codex home.
type Home struct {
	Dir string
}

// Options shapes a synthetic home.
type Options struct {
	Rollouts   int
	Marker     string
	WithWAL    bool // write state_5.sqlite-wal next to state_5.sqlite
	WithLocks  bool // create thread-writer-locks/<id>.lock files (unheld)
	RolloutAge time.Duration
	Cwd        string // cwd recorded in session_meta; "" = <parent of the home>/codextest-workspace
}

// New writes a synthetic home under dir.
func New(t testing.TB, dir string, o Options) *Home {
	t.Helper()
	return newHome(t, dir, o)
}

// HoldWriterLock flocks thread-writer-locks/<id>.lock until release is called.
func (h *Home) HoldWriterLock(t testing.TB, id string) (release func()) {
	t.Helper()
	return holdWriterLock(t, h, id)
}

// Rollouts lists rollout paths.
func (h *Home) Rollouts(t testing.TB) []string {
	t.Helper()
	return rollouts(t, h)
}

// Appender simulates Codex's rollout writer: it keeps the rollout open with
// O_APPEND and appends one Codex-shaped record every interval; Stop ends it.
type Appender struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	t        testing.TB
	path     string
	every    time.Duration

	// Owned by the writer goroutine; read by Stop after done is closed.
	count    int
	failures int
	firstErr error
}

// StartAppender starts an appender on path.
func StartAppender(t testing.TB, path string, every time.Duration) *Appender {
	t.Helper()
	return startAppender(t, path, every)
}

// Stop stops the appender and returns the number of records written.
func (a *Appender) Stop() int { return a.stopAppender() }
