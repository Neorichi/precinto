package codextest

import (
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
}

// New writes a synthetic home under dir.
func New(t testing.TB, dir string, o Options) *Home { panic("unimplemented: codextest.New") }

// HoldWriterLock flocks thread-writer-locks/<id>.lock until release is called.
func (h *Home) HoldWriterLock(t testing.TB, id string) (release func()) {
	panic("unimplemented: codextest.Home.HoldWriterLock")
}

// Rollouts lists rollout paths.
func (h *Home) Rollouts(t testing.TB) []string { panic("unimplemented: codextest.Home.Rollouts") }
