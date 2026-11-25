package sweep

import (
	"context"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep/queue"
)

// unlockedRoot is Env.Grants with the test folder unlocked.
func unlockedRoot(context.Context) (map[string]bool, error) {
	return map[string]bool{rootID: true}, nil
}

// queueAt queues a SessionEnd-style request for sid made at at, whose
// writer has exited.
func queueAt(t *testing.T, te *testEnv, sid string, at time.Time) {
	t.Helper()
	_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sid, Reason: "other",
		WaitFor: platform.ProcID{PID: 999999, StartUS: 1}, At: at})
	mustNoErr(t, err)
}

// D133 (U6-3): a request queued when a session ended does not remove the
// session a restore placed after it: the user unlocked (or unprotected)
// and restored it since, and nothing would restore it again.
func TestD133StaleRequestLeavesARestoredSession(t *testing.T) {
	for _, drain := range []string{"seal --queue", "sweep"} {
		t.Run(drain, func(t *testing.T) {
			te := newTestEnv(t)
			u, _ := te.sealedSession(sid1, nil)
			queueAt(t, te, sid1, te.run().now()) // the session's end
			te.h.Clock.Advance(time.Minute)
			if res := outcome(t, te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}}), u.Key); res.Outcome != OutRestored {
				t.Fatalf("restore %+v", res)
			}
			// The folder is unlocked: a sweep leaves the restored session
			// alone, and so must the stale request.
			te.e.Grants = unlockedRoot
			var rep *Report
			var err error
			if drain == "sweep" {
				rep, err = te.run().sweep(tctx(t), Options{})
			} else {
				rep, err = te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
			}
			mustNoErr(t, err)
			if !exists(transcriptOf(u)) {
				t.Fatalf("a request queued before the restore removed the restored session: %+v", rep.Units)
			}
			if n := len(te.logged(u.Key)); n != 1 {
				t.Fatalf("%d generations, want the first only", n)
			}
			if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
				t.Fatalf("the stale request stayed queued: %+v", reqs)
			}
			found := false
			for _, r := range rep.Units {
				if r.Unit == u.Key && r.Outcome == OutSkipped && r.Detail == detailRestoredSince {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %q result in %+v", detailRestoredSince, rep.Units)
			}
		})
	}
}

// A session that ended after its restore (a resumed session) is sealed
// for its request, also when an older request names it too: the newest
// request counts.
func TestD133RequestAfterTheRestoreSeals(t *testing.T) {
	for _, older := range []bool{false, true} {
		te := newTestEnv(t)
		u, _ := te.sealedSession(sid1, nil)
		if older {
			queueAt(t, te, sid1, te.run().now())
		}
		te.h.Clock.Advance(time.Minute)
		te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
		te.h.Clock.Advance(time.Minute)
		queueAt(t, te, sid1, te.run().now()) // the resumed session ended
		te.e.Grants = unlockedRoot
		rep, err := te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
		mustNoErr(t, err)
		if exists(transcriptOf(u)) {
			t.Fatalf("older=%v: the session that ended after its restore stayed plaintext: %+v", older, rep.Units)
		}
		if res := outcome(t, rep, u.Key); res.Outcome != OutUnchanged {
			t.Fatalf("older=%v: %+v, want dropped as unchanged", older, res)
		}
		if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
			t.Fatalf("older=%v: queue left %+v", older, reqs)
		}
	}
}

// D138: a dry run (sweep --dry-run, seal --queue --dry-run) changes
// nothing, the queue included: its "sealed" results sealed nothing. A
// sweep it turned away (sweep.requested) is left to a real sweep: a dry
// run never runs that rescan for real, and stamps no sweep.last.
func TestD138DryRunLeavesTheQueue(t *testing.T) {
	for _, tc := range []struct {
		drain     string
		requested bool // a sweep was turned away: sweep.requested exists
	}{
		{"sweep", false}, {"seal --queue", false}, {"sweep", true}, {"seal --queue", true},
	} {
		te := newTestEnv(t)
		te.writeSession(sid1, "", nil)
		u := te.scanSession(sid1)
		queueAt(t, te, sid1, te.run().now())
		_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sid2, Reason: "other"})
		mustNoErr(t, err) // nothing in plaintext: a real drain removes it
		if tc.requested {
			mustNoErr(t, te.run().touch(te.h.Layout.SweepRequested))
		}
		var rep *Report
		if tc.drain == "sweep" {
			rep, err = te.run().sweep(tctx(t), Options{DryRun: true})
		} else {
			rep, err = te.run().drainCommand(tctx(t), Options{DryRun: true})
		}
		mustNoErr(t, err)
		for _, r := range rep.Units {
			if r.Unit == u.Key && r.Detail != "dry-run" {
				t.Fatalf("%+v: %+v", tc, r)
			}
		}
		if res := outcome(t, rep, u.Key); res.Detail != "dry-run" {
			t.Fatalf("%+v: %+v", tc, res)
		}
		if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 2 {
			t.Fatalf("%+v: the dry run changed the queue: %+v", tc, reqs)
		}
		if !exists(transcriptOf(u)) {
			t.Fatalf("%+v: the dry run sealed", tc)
		}
		if tc.requested && !exists(te.h.Layout.SweepRequested) {
			t.Fatalf("%+v: the dry run took the turned-away sweep's request", tc)
		}
		if exists(te.h.Layout.SweepLast) {
			t.Fatalf("%+v: the dry run stamped sweep.last (no sweep ran)", tc)
		}
	}
}
