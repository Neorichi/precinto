package harness_test

import (
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness"
)

// SPEC §12.7: max(8 s, SessionEnd budget + 6 s), capped at 70 s.
func TestKillGrace(t *testing.T) {
	for budget, want := range map[time.Duration]time.Duration{
		0:                       8 * time.Second,
		1500 * time.Millisecond: 8 * time.Second,
		3 * time.Second:         9 * time.Second,
		30 * time.Second:        36 * time.Second,
		80 * time.Second:        70 * time.Second,
	} {
		if got := harness.KillGrace(budget); got != want {
			t.Errorf("KillGrace(%v) = %v, want %v", budget, got, want)
		}
	}
}
