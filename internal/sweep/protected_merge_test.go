package sweep

import (
	"context"
	"testing"
	"time"
)

// protectedAnswer is an Env.Protected that answers ids (ok) or nothing.
func protectedAnswer(ok bool, ids ...string) func(context.Context) (map[string]bool, bool) {
	return func(context.Context) (map[string]bool, bool) {
		if !ok {
			return nil, false
		}
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m, true
	}
}

// D151 (D133 with D142): a run judges "no longer protected" by the source
// its folders came from, Env.Protected, not by config.toml alone. A folder
// config.toml dropped while the confirmed settings or the agent still
// hold it (a removal waiting for its confirmation, D48) stays protected,
// so its queued session is sealed; Protected answering nothing keeps every
// folder (seal on doubt); a folder Protected leaves out is left in place.
func TestD151QueuedSessionFollowsProtected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protected func(context.Context) (map[string]bool, bool)
		left      bool
	}{
		{"removal waits for its confirmation", protectedAnswer(true, rootID), false},
		{"no answer", protectedAnswer(false), false},
		{"removal confirmed", protectedAnswer(true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			te.writeSession(sid1, "", nil) // ended, never sealed
			u := te.scanSession(sid1)
			queueAt(t, te, sid1, te.run().now())
			te.e.Grants = unlockedRoot
			unprotectOnDisk(t, te) // config.toml no longer lists the folder
			te.e.Protected = tc.protected
			rep, err := te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
			mustNoErr(t, err)
			res := outcome(t, rep, u.Key)
			if tc.left {
				if res.Outcome != OutSkipped || res.Detail != detailUnprotectedNow || !exists(transcriptOf(u)) {
					t.Fatalf("%+v, want %q and the plaintext", res, detailUnprotectedNow)
				}
				return
			}
			if res.Outcome != OutSealed || exists(transcriptOf(u)) {
				t.Fatalf("%+v: the session of a protected folder was left in plaintext", res)
			}
		})
	}
}

// D151: a lock sweep whose folder's removal from config.toml happens
// during its quiet wait, unconfirmed (the agent and the confirmed
// settings still hold the folder), seals the folder's session and note
// after the wait.
func TestD151LockSweepSealsAFolderWhoseRemovalWaits(t *testing.T) {
	te, _, sl := d63Env(t)
	te.writeSession(sid1, "", nil)
	p := te.note("docs/notes.md", "body\n")
	te.claude.mdPaths[sid1] = []string{p}
	u := te.scanSession(sid1)
	te.e.Grants = func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }
	te.e.Protected = protectedAnswer(true, rootID)
	te.e.Sleep = func(ctx context.Context, d time.Duration) error {
		if d == d63Quiet {
			unprotectOnDisk(t, te)
		}
		return sl.sleep(ctx, d)
	}
	rep, err := te.run().sweep(tctx(t), Options{Reason: "lock", Lock: true})
	mustNoErr(t, err)
	res, note := outcome(t, rep, u.Key), outcome(t, rep, te.noteKey("docs/notes.md"))
	if res.Outcome != OutSealed || exists(transcriptOf(u)) || note.Outcome != OutSealed || exists(p) {
		t.Fatalf("a folder whose removal waits: session %+v, note %+v, want both sealed", res, note)
	}
}
