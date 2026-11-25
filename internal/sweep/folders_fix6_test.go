package sweep

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/sweep/queue"
)

// unprotectOnDisk rewrites config.toml without the test folder, as
// `precinto unprotect` does, while a run started before keeps it in its
// own configuration.
func unprotectOnDisk(t *testing.T, te *testEnv) {
	t.Helper()
	cfg := te.h.Cfg
	cfg.Roots = nil
	mustNoErr(t, config.Save(te.h.Layout.ConfigFile, cfg))
}

// restoredAfterARequest seals a session, queues its SessionEnd request and
// restores the session a minute later: the request is stale.
func restoredAfterARequest(t *testing.T, te *testEnv) harness.Unit {
	t.Helper()
	u, _ := te.sealedSession(sid1, nil)
	queueAt(t, te, sid1, te.run().now())
	te.h.Clock.Advance(time.Minute)
	if res := outcome(t, te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}}), u.Key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	return u
}

// drainWith runs a lock sweep or a queue worker.
func drainWith(t *testing.T, te *testEnv, drain string) *Report {
	t.Helper()
	var rep *Report
	var err error
	if drain == "lock sweep" {
		rep, err = te.run().sweep(tctx(t), Options{Reason: "lock", Lock: true})
	} else {
		rep, err = te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
	}
	mustNoErr(t, err)
	return rep
}

// D133 (U6-3 regression): a stale request leaves a restored session only
// in a folder that is open when it is sealed. Locked again (the user
// worked and locked, the request still queued), the queued job seals the
// restored session as the lock sweep would: no plaintext stays in a
// locked folder, through the lock sweep (which leaves a queued unit to
// its queued job) or the queue worker.
func TestD133LockedAgainSealsTheRestoredSession(t *testing.T) {
	for _, drain := range []string{"lock sweep", "seal --queue"} {
		t.Run(drain, func(t *testing.T) {
			te := newTestEnv(t)
			u := restoredAfterARequest(t, te)
			te.h.Clock.Advance(3 * time.Hour) // locked again (no Grants: every folder is locked)
			rep := drainWith(t, te, drain)
			if exists(transcriptOf(u)) {
				t.Fatalf("the restored session stayed plaintext in a locked folder: %+v", rep.Units)
			}
			if res := outcome(t, rep, u.Key); res.Outcome != OutUnchanged {
				t.Fatalf("%+v, want dropped as unchanged", res)
			}
			if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
				t.Fatalf("queue left %+v", reqs)
			}
		})
	}
}

// D133 (U6-3): a run that started before `precinto unprotect` (D110's
// sweep in its quiet wait) still has the folder in its configuration;
// config.toml on disk no longer lists it, so a stale request leaves the
// restored session in the folder that is no longer protected.
func TestD133UnprotectedFolderKeepsTheRestoredSession(t *testing.T) {
	for _, drain := range []string{"lock sweep", "seal --queue"} {
		t.Run(drain, func(t *testing.T) {
			te := newTestEnv(t)
			u := restoredAfterARequest(t, te)
			unprotectOnDisk(t, te)
			rep := drainWith(t, te, drain)
			if !exists(transcriptOf(u)) {
				t.Fatalf("a stale request removed the restored session of an unprotected folder: %+v", rep.Units)
			}
			if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped || res.Detail != detailRestoredSince {
				t.Fatalf("%+v, want %q", res, detailRestoredSince)
			}
			if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
				t.Fatalf("the stale request stayed queued: %+v", reqs)
			}
		})
	}
}

// U6-3: a sweep judges the units it decides after its quiet wait by the
// folders' state after the wait. A folder the user unlocks (or
// unprotects) during a lock sweep's wait keeps its session and its note
// in plaintext; one still locked is sealed. The units are decided under
// their unit lock, so the check is as late as it can be.
func TestSweepJudgesTheFolderAfterTheQuietWait(t *testing.T) {
	for _, tc := range []struct {
		name   string
		during func(t *testing.T, te *testEnv, open *atomic.Bool)
		detail string // "" : sealed
	}{
		{"still locked", func(*testing.T, *testEnv, *atomic.Bool) {}, ""},
		{"unlocked during the wait", func(_ *testing.T, _ *testEnv, open *atomic.Bool) { open.Store(true) }, detailUnlockedNow},
		{"unprotected during the wait", func(t *testing.T, te *testEnv, _ *atomic.Bool) { unprotectOnDisk(t, te) }, detailUnprotectedNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te, _, sl := d63Env(t)
			te.writeSession(sid1, "", nil)
			p := te.note("docs/notes.md", "body\n")
			te.claude.mdPaths[sid1] = []string{p}
			u := te.scanSession(sid1)
			var open atomic.Bool
			te.e.Grants = func(context.Context) (map[string]bool, error) {
				if open.Load() {
					return map[string]bool{rootID: true}, nil
				}
				return map[string]bool{}, nil
			}
			te.e.Sleep = func(ctx context.Context, d time.Duration) error {
				if d == d63Quiet {
					tc.during(t, te, &open)
				}
				return sl.sleep(ctx, d)
			}
			rep, err := te.run().sweep(tctx(t), Options{Reason: "lock", Lock: true})
			mustNoErr(t, err)
			if len(sl.d) != 1 {
				t.Fatalf("quiet waits %v", sl.d)
			}
			res, note := outcome(t, rep, u.Key), outcome(t, rep, te.noteKey("docs/notes.md"))
			if tc.detail == "" {
				if res.Outcome != OutSealed || exists(transcriptOf(u)) || note.Outcome != OutSealed || exists(p) {
					t.Fatalf("a folder locked throughout: session %+v, note %+v", res, note)
				}
				return
			}
			if res.Outcome != OutSkipped || res.Detail != tc.detail || !exists(transcriptOf(u)) {
				t.Fatalf("session %+v, want %q and its plaintext", res, tc.detail)
			}
			if note.Outcome != OutSkipped || note.Detail != tc.detail || !exists(p) {
				t.Fatalf("note %+v, want %q and its plaintext", note, tc.detail)
			}
		})
	}
}

// U6-3: a queued request seals nothing in a folder that is no longer
// protected — a run started now would not even find the session there —
// though the run draining it still lists the folder (it started before
// `precinto unprotect`). In a folder still protected the same request
// seals the session whatever the folder's state (SPEC §10.1).
func TestQueuedSessionOfAnUnprotectedFolderIsLeftInPlace(t *testing.T) {
	for _, unprotected := range []bool{false, true} {
		te := newTestEnv(t)
		te.writeSession(sid1, "", nil) // ended, never sealed
		u := te.scanSession(sid1)
		queueAt(t, te, sid1, te.run().now())
		te.e.Grants = unlockedRoot // unprotect needs the folder unlocked; so does this control
		if unprotected {
			unprotectOnDisk(t, te)
		}
		rep, err := te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
		mustNoErr(t, err)
		res := outcome(t, rep, u.Key)
		if !unprotected {
			if res.Outcome != OutSealed || exists(transcriptOf(u)) {
				t.Fatalf("protected folder: %+v", res)
			}
			continue
		}
		if res.Outcome != OutSkipped || res.Detail != detailUnprotectedNow || !exists(transcriptOf(u)) {
			t.Fatalf("unprotected folder: %+v, want %q and the plaintext", res, detailUnprotectedNow)
		}
		if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
			t.Fatalf("the request stayed queued: %+v", reqs)
		}
	}
}
