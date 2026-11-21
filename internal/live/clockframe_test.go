package live_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/testkit"
)

// TestDecisionsFollowTheInjectedClock (D77, TESTPLAN §1.4): every time the
// engine compares — file and directory mtimes (R16), the restore time of a
// receipt — is compared with its injected clock, never with the system
// clock. Fixtures whose every observed path has an mtime far in the past
// or in the future of the clock get the documented verdicts for a clock
// frozen at testkit.Epoch, far before and after it, and a year before and
// after the system clock, so the outcome cannot depend on today's date.
func TestDecisionsFollowTheInjectedClock(t *testing.T) {
	t.Parallel()
	const year = 365 * 24 * time.Hour
	for _, c := range []struct {
		name  string
		start time.Time
	}{
		{"epoch", testkit.Epoch},
		{"30 years before epoch", testkit.Epoch.Add(-30 * year)},
		{"70 years after epoch", testkit.Epoch.Add(70 * year)},
		{"a year behind the system clock", time.Now().Add(-year)},
		{"a year ahead of the system clock", time.Now().Add(year)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			clock := fakeplatform.NewClock(c.start)
			dir := t.TempDir()
			e := &live.Engine{Procs: fakeplatform.NewProcs(), Clock: clock, LeasesDir: filepath.Join(dir, "leases"),
				Observer: live.NewObserver(clock), Quiet: quiet, HoldCap: 24 * time.Hour}
			now := clock.Now()
			// A unit is a directory and a file in it, both stamped at.
			unit := func(name string, at time.Time) live.Subject {
				t.Helper()
				d := filepath.Join(dir, name)
				f := filepath.Join(d, name+".jsonl")
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, p := range []string{f, d} { // the directory last: the file changed its mtime
					if err := os.Chtimes(p, at, at); err != nil {
						t.Fatal(err)
					}
				}
				return live.Subject{Key: "unit-" + name, Paths: []string{d, f}}
			}
			decide := func(s live.Subject) live.Verdict {
				t.Helper()
				v, err := e.Decide(context.Background(), s, nil)
				if err != nil {
					t.Fatalf("Decide(%s): %v", s.Key, err)
				}
				return v
			}
			subjects := map[string]live.Subject{
				"old":       unit("old", now.Add(-10*year)),      // far in the past of the clock
				"recent":    unit("recent", now.Add(-time.Hour)), // in its past
				"skew":      unit("skew", now.Add(time.Second)),  // within the 2 s of file-time rounding
				"future":    unit("future", now.Add(time.Hour)),  // beyond the quiet window too,
				"far":       unit("far", now.Add(10*year)),       // far in the future of the clock
				"restored":  unit("restored", now.Add(-time.Hour)),
				"restore10": unit("restore10", now.Add(-time.Hour)),
			}
			restoredRecently := subjects["restored"]
			restoredRecently.RestoredAt = now.Add(-30 * time.Second) // within the quiet window of the clock
			subjects["restored"] = restoredRecently
			restoredLongAgo := subjects["restore10"]
			restoredLongAgo.RestoredAt = now.Add(-10 * year)
			subjects["restore10"] = restoredLongAgo

			// First look: nothing proves stability yet (D63), and only the
			// fixtures in the clock's future are "in the future".
			for name, s := range subjects {
				v := decide(s)
				if !v.Live || !reasons(v)[live.ReasonUnobserved] {
					t.Errorf("%s, first look: %+v, want live and unobserved", name, v)
				}
				future := name == "future" || name == "far"
				if got := reasons(v)[live.ReasonFutureTime]; got != future {
					t.Errorf("%s, first look: future-mtime = %v, want %v (%+v)", name, got, future, v)
				}
			}
			// A quiet window later on the clock: the past fixtures are
			// stable and sealable, the future ones stay live on weak
			// evidence only, and a restore 30 s before the first look is
			// past the window too.
			clock.Advance(quiet)
			for name, s := range subjects {
				v := decide(s)
				switch name {
				case "future", "far":
					if !v.Live || !reasons(v)[live.ReasonFutureTime] {
						t.Errorf("%s after the window: %+v, want live with future-mtime (R16)", name, v)
					}
					for _, ev := range v.Evidence {
						if !ev.Weak {
							t.Errorf("%s after the window: strong evidence %+v (a future mtime is weak, S14)", name, ev)
						}
					}
				default:
					if v.Live {
						t.Errorf("%s after the window: %+v, want not live", name, v)
					}
				}
			}
			// A restore stamped by the clock just now holds the unit for a
			// quiet window of the clock, whatever the system time says.
			s := subjects["recent"]
			s.RestoredAt = clock.Now().Add(-time.Second)
			if v := decide(s); !v.Live || !reasons(v)[live.ReasonUnstable] {
				t.Errorf("restored a second ago on the clock: %+v, want live", v)
			}
			s.RestoredAt = clock.Now().Add(-quiet - time.Second)
			if v := decide(s); v.Live {
				t.Errorf("restored a quiet window ago on the clock: %+v, want not live", v)
			}
		})
	}
}
