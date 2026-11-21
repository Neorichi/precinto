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
	"github.com/precinto/precinto/internal/sweep/queue"
)

// lookingLive mimics the engine's two-look stability (D63): the first
// Decide of a key adds a first observation (weak) to the adapter's
// evidence; later ones add nothing, unless changed marks the key unstable.
// R20: a reaped writer with no other evidence skips the window.
type lookingLive struct {
	mu      sync.Mutex
	seen    map[string]int
	changed map[string]bool
}

func (l *lookingLive) Decide(ctx context.Context, s live.Subject, extra []live.Evidence) (live.Verdict, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[s.Key]++
	ev := append([]live.Evidence(nil), extra...)
	if !s.WriterExited || len(extra) > 0 {
		switch {
		case l.seen[s.Key] == 1:
			ev = append(ev, live.Evidence{Reason: live.ReasonUnobserved, Weak: true})
		case l.changed[s.Key]:
			ev = append(ev, live.Evidence{Reason: live.ReasonUnstable})
		}
	}
	return live.Verdict{Live: len(ev) > 0, Evidence: ev}, nil
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
	rep, err := te.run().sealCommand(tctx(t), units, Options{})
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
	rep, _ = te2.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
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
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, o)
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
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{WaitFor: &pid})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || len(sl.d) != 0 {
		t.Fatalf("writer exited: %+v after %v", res, sl.d)
	}
}

// A sweep drains the queue and seals its own units in one pair of
// decision passes: one quiet-window wait for everything (D63), the queued
// unit sealed once.
func TestD63QueueAndSweepShareOneWait(t *testing.T) {
	te, l, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	te.writeSession(sid2, "", nil)
	_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sid1, Reason: "other"})
	mustNoErr(t, err)
	k1, k2 := te.scanSession(sid1).Key, te.scanSession(sid2).Key
	rep, err := te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if len(sl.d) != 1 {
		t.Fatalf("sleeps %v, want exactly one quiet-window wait", sl.d)
	}
	for _, k := range []string{k1, k2} {
		n := 0
		for _, u := range rep.Units {
			if u.Unit == k {
				n++
				if u.Outcome != OutSealed {
					t.Fatalf("%s: %+v", short(k), u)
				}
			}
		}
		if n != 1 || l.seen[k] != 2 {
			t.Fatalf("%s reported %d times, decided %d times", short(k), n, l.seen[k])
		}
	}
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatalf("queue left %+v", reqs)
	}
}

// SPEC §9.5: a unit of a locked folder still held only by weak evidence
// after the quiet wait is reported hold-capped; in an unlocked folder it
// is plainly live.
func TestD63HoldCappedAfterTheWait(t *testing.T) {
	for _, unlocked := range []bool{false, true} {
		te, _, sl := d63Env(t)
		te.writeSession(sid1, "", nil)
		u := te.scanSession(sid1)
		te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonRegistry, Detail: "registry names the session", Weak: true}}
		if unlocked {
			te.e.Grants = func(context.Context) (map[string]bool, error) { return map[string]bool{rootID: true}, nil }
		}
		rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
		res := outcome(t, rep, u.Key)
		want := codeLive + ": " + reasonHoldCapped
		if unlocked {
			want = codeLive + ": registry"
		}
		if res.Outcome != OutLive || res.Detail != want || len(sl.d) != 1 || !exists(transcriptOf(u)) {
			t.Fatalf("unlocked=%v: %+v after %v", unlocked, res, sl.d)
		}
		if unlocked {
			continue
		}
		// A sweep reports it bare; the session stays plaintext.
		rep, _ = te.run().sweep(tctx(t), Options{})
		if res := outcome(t, rep, u.Key); res.Outcome != OutLive || res.Detail != reasonHoldCapped {
			t.Fatalf("sweep: %+v", res)
		}
	}
}

// A note whose writer session the same sweep seals is sealed in that
// sweep too: the run's decision stands for the writer, whose plaintext is
// gone, and the note's own first look was primed before the wait.
func TestD63NoteOfASessionSealedInTheSameSweep(t *testing.T) {
	te, _, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	p := te.note("docs/notes.md", "body\n")
	te.claude.mdPaths[sid1] = []string{p}
	u := te.scanSession(sid1)
	rep, err := te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("session %+v", res)
	}
	if res := outcome(t, rep, te.noteKey("docs/notes.md")); res.Outcome != OutSealed {
		t.Fatalf("note %+v", res)
	}
	if exists(p) || !exists(p+".precinto") || len(sl.d) != 1 {
		t.Fatalf("note plaintext left (or no marker) after %v", sl.d)
	}
}

// SealMarkdown primes the note's writer sessions as well: a writer that is
// only first-observed does not hold the note after the wait.
func TestD63SealMarkdownPrimesWriters(t *testing.T) {
	te, l, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	p := te.note("docs/notes.md", "body\n")
	te.claude.mdPaths[sid1] = []string{p}
	u := te.scanSession(sid1)
	r := te.run()
	root := te.root()
	cands := r.noteCandidates(tctx(t), root)
	if r.primeNotes(tctx(t), root, cands, nil) {
		r.waitQuiet(tctx(t), time.Time{})
	}
	r.sealMarkdown(tctx(t), root, Options{}, cands)
	rep := r.finish()
	if res := outcome(t, rep, te.noteKey("docs/notes.md")); res.Outcome != OutSealed {
		t.Fatalf("note %+v (writer decided %d times)", res, l.seen[u.Key])
	}
	if len(sl.d) != 1 || !exists(transcriptOf(u)) {
		t.Fatalf("sleeps %v, or the writer session was touched", sl.d)
	}
}

// SPEC §10.2 with D63: the lock holder's rescan for a sweep it turned away
// is a sweep of its own — every locked folder, its own quiet wait — so a
// session that appeared (or whose folder locked) during the first pass is
// sealed before the holder exits.
func TestD63RescanIsASweepWithItsOwnWait(t *testing.T) {
	te, _, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	written := false
	te.e.Sleep = func(ctx context.Context, d time.Duration) error {
		if d == d63Quiet && !written {
			// During the first pass: a session appears and another sweep,
			// turned away, asks for the rescan.
			written = true
			te.writeSession(sid2, "", nil)
			mustNoErr(t, te.run().touch(te.h.Layout.SweepRequested))
		}
		return sl.sleep(ctx, d)
	}
	rep, err := te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, te.sessionKey(sid2)); res.Outcome != OutSealed {
		t.Fatalf("session of the rescan %+v", res)
	}
	if len(sl.d) != 2 {
		t.Fatalf("quiet waits %v, want one per pass", sl.d)
	}
}

// A queue worker that holds the sweep lock runs the sweep it turned away
// (sweep.requested): the queue drain and every locked folder.
func TestQueueWorkerRunsTheTurnedAwaySweep(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	mustNoErr(t, te.run().touch(te.h.Layout.SweepRequested))
	rep, err := te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("the turned-away sweep did not run: %+v", res)
	}
	if exists(te.h.Layout.SweepRequested) || !exists(te.h.Layout.SweepLast) {
		t.Fatal("sweep.requested left or sweep.last not stamped")
	}
	// Busy: another holder makes the worker leave the drain to it.
	lk, err := te.run().lockName("sweep")
	mustNoErr(t, err)
	defer lk.Unlock()
	if _, err := te.run().drainCommand(tctx(t), Options{}); err != ErrBusy || !exists(te.h.Layout.SweepRequested) {
		t.Fatalf("drain while the lock is held: %v (want ErrBusy and sweep.requested)", err)
	}
}
