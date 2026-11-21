package sweep

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
)

// lookingLive mimics the engine's two-look stability (D63): the first
// Decide of a key is live by first observation only; later ones are not
// live, unless changed marks the key unstable.
type lookingLive struct {
	mu      sync.Mutex
	seen    map[string]int
	changed map[string]bool
}

func (l *lookingLive) Decide(ctx context.Context, s live.Subject, extra []live.Evidence) (live.Verdict, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[s.Key]++
	if len(extra) > 0 {
		return live.Verdict{Live: true, Evidence: extra}, nil
	}
	if s.WriterExited {
		return live.Verdict{}, nil // R20: no stability window
	}
	switch {
	case l.seen[s.Key] == 1:
		return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnobserved, Weak: true}}}, nil
	case l.changed[s.Key]:
		return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnstable}}}, nil
	}
	return live.Verdict{}, nil
}

func (l *lookingLive) StillQuiet(ctx context.Context, s live.Subject, snaps map[string]fsx.Stat) (bool, error) {
	return true, nil
}

// sleeps records the quiet-window waits among the Env.Sleep calls (the
// run's other waits, such as the 1 s rescue grace, use it too).
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

const d63Quiet = 30 * time.Second

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d == d63Quiet {
		s.d = append(s.d, d)
	}
	return ctx.Err()
}

func d63Env(t *testing.T) (*testEnv, *lookingLive, *sleeps) {
	te := newTestEnv(t)
	l := &lookingLive{seen: map[string]int{}, changed: map[string]bool{}}
	te.p.live = l
	sl := &sleeps{}
	te.e.Sleep = sl.sleep
	te.e.Live = &live.Engine{Quiet: d63Quiet}
	return te, l, sl
}

// A never-observed unit causes exactly one Sleep(quiet) per run and is
// then sealed.
func TestD63OneWaitThenSealed(t *testing.T) {
	te, l, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	te.writeSession(sid2, "", nil)
	units := []harness.Unit{te.scanSession(sid1), te.scanSession(sid2)}
	rep, err := te.run().sealCommand(context.Background(), units, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sl.d) != 1 || sl.d[0] != d63Quiet {
		t.Fatalf("sleeps %v, want exactly one of the quiet window", sl.d)
	}
	for _, u := range units {
		if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
			t.Fatalf("%s: %+v", u.Key, res)
		}
		if l.seen[u.Key] != 2 {
			t.Fatalf("%s decided %d times, want two looks", u.Key, l.seen[u.Key])
		}
	}
	// A unit that changed between the looks stays live.
	te2, l2, sl2 := d63Env(t)
	te2.writeSession(sid1, "", nil)
	u := te2.scanSession(sid1)
	l2.changed[u.Key] = true
	rep, _ = te2.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive || len(sl2.d) != 1 {
		t.Fatalf("changed unit: %+v after %v", res, sl2.d)
	}
}

// A deadline shorter than the quiet window: no Sleep, the unit is
// reported live ("unobserved").
func TestD63ShortDeadlineSkipsTheWait(t *testing.T) {
	te, _, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	o := Options{Deadline: te.run().now().Add(5 * time.Second)}
	rep, _ := te.run().sealCommand(context.Background(), []harness.Unit{u}, o)
	res := outcome(t, rep, u.Key)
	if len(sl.d) != 0 || res.Outcome != OutLive || res.Detail != codeLive+": unobserved" {
		t.Fatalf("short deadline: %+v after %v", res, sl.d)
	}
}

// R20: when the only known writer was reaped (--wait-pid) the seal does
// not wait.
func TestD63WriterExitedNeedsNoWait(t *testing.T) {
	te, _, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	pid := platform.ProcID{PID: 999999, StartUS: 1} // not in the process table: exited
	rep, _ := te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{WaitFor: &pid})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || len(sl.d) != 0 {
		t.Fatalf("writer exited: %+v after %v", res, sl.d)
	}
}
