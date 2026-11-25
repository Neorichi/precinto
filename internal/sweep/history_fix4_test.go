package sweep

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/claude/claudetest"
	"github.com/Neorichi/precinto/internal/testkit"
)

// D89 (DATA-7): rotate, merge back, rotate with no new prompt: no new
// history generation, the protected lines leave history.jsonl again and
// merge-back still restores them. One new prompt then makes exactly one
// generation holding only that line.
func TestRotationDoesNotSealMergedLinesAgain(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	l := claudetest.New(t, te.h.Dir)
	l.WriteHistory(t, te.h.Root, sid1, 6, testkit.Marker(t))
	all := te.historyLines()
	rotate := func() *Report {
		r := te.run()
		r.rotateHistory(tctx(t))
		return r.finish()
	}
	merge := func() {
		r := te.run()
		r.mergeHistory(tctx(t), te.keys, rootID)
	}
	if rep := rotate(); rep.Count(OutSealed) != 1 {
		t.Fatalf("rotation 1 %+v", rep.Units)
	}
	sealed := len(te.sealedHistory())
	for cycle := 2; cycle <= 4; cycle++ {
		merge()
		if n := len(te.historyLines()); n != len(all) {
			t.Fatalf("cycle %d: merge-back gave %d lines, want %d", cycle, n, len(all))
		}
		if rep := rotate(); rep.Count(OutSealed) != 1 {
			t.Fatalf("rotation %d %+v", cycle, rep.Units)
		}
		if n := len(te.logged(te.historyKey())); n != 1 {
			t.Fatalf("cycle %d: %d history generations, want 1", cycle, n)
		}
		for _, ln := range te.historyLines() {
			if testHistoryLine([]byte(ln)).Project == te.h.Root {
				t.Fatalf("cycle %d: a protected line stayed in history.jsonl", cycle)
			}
		}
	}
	merge()
	appendLines(t, te.historyPath(), historyLineFor(te.h.Root, "one new prompt", time.Now().UnixMilli(), ""))
	if rep := rotate(); rep.Count(OutSealed) != 1 {
		t.Fatalf("rotation with a new prompt %+v", rep.Units)
	}
	if n := len(te.logged(te.historyKey())); n != 2 {
		t.Fatalf("%d history generations, want 2", n)
	}
	if got := len(te.sealedHistory()); got != sealed+1 {
		t.Fatalf("sealed lines %d, want %d (only the new prompt)", got, sealed+1)
	}
}

// D89: a seen set that relies on a generation no longer logged (forget)
// is ignored, so the lines are sealed again rather than dropped.
func TestRotationSealsAgainWhenTheSeenGenerationIsGone(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	l := claudetest.New(t, te.h.Dir)
	l.WriteHistory(t, te.h.Root, sid1, 3, testkit.Marker(t))
	r := te.run()
	r.rotateHistory(tctx(t))
	te.run().mergeHistory(tctx(t), te.keys, rootID)
	// The seen set names a generation that is not logged.
	s := te.run().loadSeen(te.historyKey(), te.logged(te.historyKey()))
	if s == nil {
		t.Fatal("no seen set after a rotation")
	}
	s.Gens = append(s.Gens, 99)
	te.run().saveSeen(te.historyKey(), s)
	r = te.run()
	r.rotateHistory(tctx(t))
	if n := len(te.logged(te.historyKey())); n != 2 {
		t.Fatalf("%d history generations, want 2 (lines sealed again)", n)
	}
}

// D76/D90 (DATA-9): below the free-space floor the rotation starts
// nothing: no history generation, history.jsonl byte-identical, no hold
// link and no journal record; merge-back appends nothing either.
func TestHistoryRespectsTheFreeSpaceFloor(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	l := claudetest.New(t, te.h.Dir)
	l.WriteHistory(t, te.h.Root, sid1, 4, testkit.Marker(t))
	before := readFile(t, te.historyPath())
	te.fs.free = 0
	r := te.run()
	r.rotateHistory(tctx(t))
	if res := outcome(t, r.finish(), te.historyKey2()); res.Outcome == OutSealed || !strings.Contains(res.Detail, "no-space") {
		t.Fatalf("rotation below the floor %+v", res)
	}
	if n := len(te.logged(te.historyKey())); n != 0 {
		t.Fatalf("%d history generation(s) written below the floor", n)
	}
	if !bytes.Equal(readFile(t, te.historyPath()), before) {
		t.Fatal("history.jsonl rewritten below the floor")
	}
	if holds, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, ".precinto-hold-*")); len(holds) != 0 {
		t.Fatalf("hold left: %v", holds)
	}
	if pending, _ := te.e.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("records left: %d", len(pending))
	}
	// Merge-back below the floor.
	te.fs.free = 1 << 50
	r = te.run()
	r.rotateHistory(tctx(t))
	after := readFile(t, te.historyPath())
	te.fs.free = 0
	mr := te.run()
	mr.mergeHistory(tctx(t), te.keys, rootID)
	if res := outcome(t, mr.finish(), te.historyKey()); res.Outcome != OutSkipped {
		t.Fatalf("merge below the floor %+v", res)
	}
	if !bytes.Equal(readFile(t, te.historyPath()), after) {
		t.Fatal("merge-back appended below the floor")
	}
}

// historyKey2 is the journal key a home's rotation reports under.
func (te *testEnv) historyKey2() string {
	k, err := te.run().historyJournalKey(te.cc)
	mustNoErr(te.t, err)
	return k
}

// D90 (DATA-10): a kept line longer than fsx.MaxLine (an unterminated
// big paste of an unprotected project) survives the rotation byte for
// byte; a sealed protected line that long comes back at merge-back.
func TestHistoryKeepsLongLines(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	now := time.Now().UnixMilli()
	longSealed := historyLineFor(te.h.Root, strings.Repeat("p", fsx.MaxLine+10), now, "")
	appendLines(t, te.historyPath(),
		historyLineFor(te.h.Root, "protected prompt", now+1, ""),
		longSealed,
		historyLineFor(te.h.HomeDir+"/elsewhere", "short unprotected prompt", now+2, ""))
	long := historyLineFor(te.h.HomeDir+"/elsewhere", strings.Repeat("x", fsx.MaxLine+10), now+3, "")
	f, err := os.OpenFile(te.historyPath(), os.O_WRONLY|os.O_APPEND, 0)
	mustNoErr(t, err)
	_, _ = f.WriteString(long)
	f.Close()
	r := te.run()
	r.rotateHistory(tctx(t))
	if res := outcome(t, r.finish(), te.historyKey2()); res.Outcome != OutSealed {
		t.Fatalf("rotation %+v", res)
	}
	b := readFile(t, te.historyPath())
	if !bytes.Contains(b, []byte(long+"\n")) {
		t.Fatal("the long unprotected line is gone from history.jsonl")
	}
	if bytes.Contains(b, []byte(longSealed)) {
		t.Fatal("the long protected line stayed")
	}
	te.run().mergeHistory(tctx(t), te.keys, rootID)
	if !bytes.Contains(readFile(t, te.historyPath()), []byte(longSealed+"\n")) {
		t.Fatal("merge-back dropped the long protected line")
	}
}

var _ = harness.ClaudeCode
