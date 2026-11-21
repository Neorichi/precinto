package sweep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/testkit"
)

// SEAL-4 and SEC-10 (sweep side): a corrupted temporary or a header with
// the wrong stanzas fails verification: exit 5, temporary gone,
// plaintext intact, nothing logged.
func TestSealVerificationFailuresKeepPlaintext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		set  func(c *fakeCodec)
		want error
	}{
		{"flipped byte", func(c *fakeCodec) { c.corrupt = true }, capsule.ErrVerify},
		{"two stanzas", func(c *fakeCodec) { c.stanzas = 2 }, capsule.ErrHeader},
		{"four stanzas", func(c *fakeCodec) { c.stanzas = 4 }, capsule.ErrHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			orig := te.original(u)
			tc.set(te.codec)
			rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
			mustNoErr(t, err)
			if res := outcome(t, rep, u.Key); res.Outcome != OutFailed || !errors.Is(rep.Err(), tc.want) {
				t.Fatalf("result %+v, Err %v", res, rep.Err())
			}
			te.plaintextIntact(orig)
			if ents := te.unitDirEntries(u.Key); len(ents) != 0 {
				t.Fatalf("leftovers %v", ents)
			}
			if len(te.logged(u.Key)) != 0 {
				t.Fatal("logged")
			}
		})
	}
}

// CODX-2: a stale -wal next to a database being placed is moved to
// quarantine; the group placed is the snapshot's.
func TestCodexStaleWALIsQuarantined(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	home := te.codexHomeDir()
	mustNoErr(t, os.MkdirAll(filepath.Dir(home), 0o700))
	codextest.New(t, home, codextest.Options{Rollouts: 2, Marker: testkit.Marker(t)})
	te.useCodex(t)
	orig := te.snapshotOf(t)
	te.sealCodex(t)
	wal := filepath.Join(home, "state_5.sqlite-wal")
	writeAt(t, wal, []byte("stale wal frames"))
	if res := te.restoreCodex(t); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	if exists(wal) {
		t.Fatal("stale -wal left next to its database")
	}
	q, _ := filepath.Glob(filepath.Join(te.h.Layout.QuarantineDir, "*", "codex", "state_5.sqlite-wal"))
	if len(q) != 1 || string(readFile(t, q[0])) != "stale wal frames" {
		t.Fatalf("not moved to quarantine (never deleted): %v", q)
	}
	for p, b := range orig {
		if string(readFile(t, p)) != string(b) {
			t.Fatalf("%s differs", filepath.Base(p))
		}
	}
}

// CONC-1: ten session-end sealers and three sweeps at once seal each unit
// exactly once, without deadlock.
func TestConcurrentSealersSealEachUnitOnce(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	sids := []string{sid1, sid2, "00000000-0000-4000-8000-0000000000a3"}
	for _, sid := range sids {
		te.writeSession(sid, "", nil)
	}
	var units []harness.Unit
	for _, sid := range sids {
		units = append(units, te.scanSession(sid))
	}
	ctx, cancel := context.WithTimeout(tctx(t), time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := units[i%len(units)]
			te.run().sealCommand(ctx, []harness.Unit{u}, Options{Reason: "session-end"})
		}(i)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := te.run().sweep(ctx, Options{Wait: true})
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		t.Fatal("deadlock")
	}
	for _, u := range units {
		if n := len(te.logged(u.Key)); n != 1 {
			t.Errorf("unit sealed %d times", n)
		}
		te.plaintextGone(u)
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		t.Fatalf("records left %+v", p)
	}
}

// SEC-8: an inode swapped in with the same size and mtime between hashing
// and the unlink is never deleted.
func TestInodeSwapBeforeUnlinkKeepsTheFile(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	victim := filepath.Join(u.Home.Bases[u.Files[0].Base], u.Files[0].Rel)
	swapped := false
	te.fs.onUnlink = func(p string) {
		if p != victim || swapped {
			return
		}
		swapped = true
		st, _ := os.Stat(victim)
		b := readFile(t, victim)
		tmp := victim + ".swap"
		writeAt(t, tmp, append([]byte(nil), b...))
		mustNoErr(t, os.Chtimes(tmp, st.ModTime(), st.ModTime()))
		mustNoErr(t, os.Rename(tmp, victim))
	}
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("result %+v", res)
	}
	if !swapped || !exists(victim) {
		t.Fatal("I3: a swapped inode was deleted")
	}
	// It stays as plaintext tracked by the receipt (as sealed); its bytes
	// equal the sealed ones, so the next seal drops it as unchanged.
	rd, ok, _ := LoadReceipt(te.e, u.Key)
	if !ok || len(rd.Files) != 1 || rd.Files[0].Rel != u.Files[0].Rel || rd.Gen != 1 {
		t.Fatalf("receipt %+v", rd)
	}
	te.fs.onUnlink = nil
	rep, _ = te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutUnchanged || exists(victim) {
		t.Fatalf("retry %+v (victim left %v)", res, exists(victim))
	}
}

// SEC-18 (sweep side): with hooks disabled (no ledger), Markdown the
// transcript shows an agent wrote is still found and sealed.
func TestTranscriptDerivedNotesAreSealed(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	p := filepath.Join(te.h.Root, "x.md")
	writeAt(t, p, []byte("written by the agent\n"))
	old := testkit.Epoch.Add(-time.Hour)
	mustNoErr(t, os.Chtimes(p, old, old))
	te.claude.mdPaths[sid1] = []string{p}
	// The session is sealed first (its transcript goes into the capsule):
	// the note candidate survives in the pending index.
	te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
	if got := te.run().pendingNotes(rootID); len(got) != 1 || got[0] != p {
		t.Fatalf("pending notes %v", got)
	}
	te.sealNotes()
	if exists(p) || !exists(p+".precinto") {
		t.Fatal("transcript-derived note not sealed")
	}
	if got := te.run().pendingNotes(rootID); len(got) != 0 {
		t.Fatalf("index not cleared: %v", got)
	}
}
