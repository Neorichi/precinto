package sweep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/testkit"
)

const sid1 = "00000000-0000-4000-8000-0000000000a1"
const sid2 = "00000000-0000-4000-8000-0000000000a2"

// writeSession writes a synthetic Claude session with marker text into the
// fake home and registers it with the fake adapter.
func (te *testEnv) writeSession(sid string, marker string, mod func(*claudetest.Session)) []string {
	te.t.Helper()
	l := claudetest.New(te.t, te.h.Dir)
	s := claudetest.Session{SID: sid, Cwd: te.h.Root, Marker: marker, Subagents: 1, ModTime: testkit.Epoch.Add(-time.Hour)}
	if mod != nil {
		mod(&s)
	}
	paths := l.WriteSession(te.t, s)
	te.claude.sids = append(te.claude.sids, sid)
	return paths
}

// sessionFiles lists the session's own files (the adapter's view).
func (te *testEnv) sessionFiles(u harness.Unit) []string {
	var out []string
	for _, f := range u.Files {
		out = append(out, filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel)))
	}
	return out
}

func TestSealSessionEndToEnd(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	marker := testkit.Marker(t)
	te.writeSession(sid1, marker, nil)
	u := te.scanSession(sid1)
	files := te.sessionFiles(u)
	if len(files) < 5 {
		t.Fatalf("synthetic session too small: %d files", len(files))
	}
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{Reason: "session-end"})
	mustNoErr(t, err)
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutSealed || res.Gen != 1 || res.Lineage != capsule.LineageFresh {
		t.Fatalf("result %+v", res)
	}
	if err := rep.Err(); err != nil {
		t.Fatalf("Err = %v", err)
	}
	en := te.logged(u.Key)
	if len(en) != 1 || en[0].Path != "claude-code/"+u.Key+"/g000001.pcap" || en[0].HeaderSHA256 == "" || en[0].Files != len(files) {
		t.Fatalf("log %+v", en)
	}
	capsulePath := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")
	if st, err := fsx.Lstat(capsulePath); err != nil || st.Perm() != 0o600 {
		t.Fatalf("capsule %+v %v", st, err)
	}
	for _, f := range files {
		if exists(f) {
			t.Errorf("plaintext left: %s", f)
		}
	}
	// The session's directories went with it (Unit.Prune).
	if exists(filepath.Join(te.h.ClaudeTmp, filepath.Base(filepath.Dir(filepath.Dir(files[0]))), sid1)) {
		t.Error("emptied tmp directory left")
	}
	if _, ok, _ := LoadReceipt(te.e, u.Key); ok {
		t.Error("receipt left although no plaintext remains")
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		t.Errorf("journal not empty: %+v", p)
	}
	// I7: no content in precinto's metadata (capsules excluded).
	if hits := testkit.GrepTree(t, te.h.Base, marker, "capsules"); len(hits) != 0 {
		t.Fatalf("marker leaked into precinto metadata: %v", hits)
	}
}

func TestSealRefusesOnTripwireAndKeepsPlaintext(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	before := snapshotTree(t, te.h.ClaudeConfig)
	te.vaults.tripwire[rootID] = true
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutFailed {
		t.Fatalf("result %+v", res)
	}
	if !errors.Is(rep.Err(), ErrTripwire) {
		t.Fatalf("Err = %v, want ErrTripwire (exit 5)", rep.Err())
	}
	if after := snapshotTree(t, te.h.ClaudeConfig); len(after) != len(before) {
		t.Fatal("plaintext touched")
	}
	if len(te.logged(u.Key)) != 0 {
		t.Fatal("capsule logged")
	}
}

func TestSealNeverTouchesALiveUnit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ev   live.Evidence
		want Outcome
	}{
		{"ledger-proc", live.Evidence{Reason: live.ReasonLedgerProc}, OutLive},
		{"lease", live.Evidence{Reason: live.ReasonLease}, OutLeased},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			before := snapshotTree(t, te.h.Dir)
			te.live.set(u.Key, live.Verdict{Live: true, Evidence: []live.Evidence{tc.ev}})
			rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
			mustNoErr(t, err)
			if res := outcome(t, rep, u.Key); res.Outcome != tc.want || len(res.Evidence) != 1 {
				t.Fatalf("result %+v", res)
			}
			if !errors.Is(rep.Err(), ErrLive) {
				t.Fatalf("explicit seal of a live unit: Err = %v, want ErrLive (exit 4)", rep.Err())
			}
			after := snapshotTree(t, te.h.Dir)
			for p, h := range before {
				if after[p] != h {
					t.Fatalf("I1: %s touched", p)
				}
			}
		})
	}
}

func TestSealProbeErrorMeansLive(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	te.claude.probeErr = errors.New("registry unreadable")
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive {
		t.Fatalf("result %+v", res)
	}
}

// SEAL-5: an appender writes between the hash pass and the copy pass.
func TestSealAbortsWhenAFileChangesBetweenPasses(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	transcript := ""
	for _, f := range u.Files {
		if f.Last {
			transcript = filepath.Join(u.Home.Bases[f.Base], f.Rel)
		}
	}
	te.codec.betweenPasses = func() {
		f, err := os.OpenFile(transcript, os.O_WRONLY|os.O_APPEND, 0)
		mustNoErr(t, err)
		_, _ = f.WriteString(`{"uuid":"00000000-0000-4000-8000-00000000ffff"}` + "\n")
		f.Close()
	}
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive {
		t.Fatalf("result %+v", res)
	}
	if !errors.Is(rep.Err(), ErrLive) {
		t.Fatalf("Err = %v, want ErrLive (exit 4)", rep.Err())
	}
	if len(te.logged(u.Key)) != 0 {
		t.Fatal("a generation was logged")
	}
	if !strings.Contains(string(readFile(t, transcript)), "ffff") {
		t.Fatal("appended bytes lost")
	}
	ents, _ := os.ReadDir(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key))
	if len(ents) != 0 {
		t.Fatalf("leftovers in the unit directory: %v", ents)
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		t.Fatalf("journal not empty: %+v", p)
	}
}

// SEC-7: symlinks, FIFOs and hard links are never followed, sealed or
// deleted; the rest of the unit is sealed.
func TestSealHazardsAreReportedNeverTouched(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	dir := filepath.Dir(filepath.Join(u.Home.Bases[u.Files[0].Base], u.Files[0].Rel))
	canary := filepath.Join(te.h.HomeDir, "canary.txt")
	mustNoErr(t, os.WriteFile(canary, []byte("canary\n"), 0o600))
	mustNoErr(t, os.Symlink(canary, filepath.Join(dir, sid1+".link")))
	mustNoErr(t, testkit.Mkfifo(filepath.Join(dir, sid1+".fifo"), 0o600))
	hard := filepath.Join(dir, sid1+"-hard.txt")
	mustNoErr(t, os.WriteFile(hard, []byte("shared\n"), 0o600))
	mustNoErr(t, os.Link(hard, filepath.Join(te.h.HomeDir, "other-link")))
	u = te.scanSession(sid1)
	if len(u.Hazards) < 3 {
		t.Fatalf("fake adapter hazards %+v", u.Hazards)
	}
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutSealed || len(res.Hazards) < 3 {
		t.Fatalf("result %+v", res)
	}
	for _, p := range []string{filepath.Join(dir, sid1+".link"), filepath.Join(dir, sid1+".fifo"), hard} {
		if !exists(p) {
			t.Errorf("hazard %s deleted", filepath.Base(p))
		}
	}
	if string(readFile(t, canary)) != "canary\n" {
		t.Fatal("canary changed")
	}
}

// D10: plaintext restored and left unchanged re-seals without a new
// generation.
func TestUnchangedResealDropsPlaintextWithoutANewGeneration(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	ctx := tctx(t)
	if rep, _ := te.run().sealCommand(ctx, []harness.Unit{u}, Options{}); outcome(t, rep, u.Key).Outcome != OutSealed {
		t.Fatal("first seal")
	}
	rep, err := te.run().restore(ctx, te.keys, RestoreRequest{Units: []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: u.Key}}})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	rd, ok, err := LoadReceipt(te.e, u.Key)
	if err != nil || !ok || rd.Gen != 1 || len(rd.Files) != len(u.Files) {
		t.Fatalf("receipt %+v %v %v", rd, ok, err)
	}
	u2 := te.scanSession(sid1)
	rep, err = te.run().sealCommand(ctx, []harness.Unit{u2}, Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutUnchanged || res.Gen != 1 {
		t.Fatalf("re-seal %+v", res)
	}
	if n := len(te.logged(u.Key)); n != 1 {
		t.Fatalf("%d generations, want 1", n)
	}
	for _, f := range te.sessionFiles(u2) {
		if exists(f) {
			t.Fatalf("plaintext left: %s", f)
		}
	}
	if _, ok, _ := LoadReceipt(te.e, u.Key); ok {
		t.Fatal("receipt left")
	}
}

// SEAL-11: EACCES on one unlink.
func TestRemoveFailedRetriesAsUnchanged(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	victim := filepath.Join(u.Home.Bases[u.Files[0].Base], u.Files[0].Rel)
	te.fs.inject("unlink", victim, syscall.EACCES)
	ctx := tctx(t)
	rep, err := te.run().sealCommand(ctx, []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutRemoveFailed || res.Gen != 1 {
		t.Fatalf("result %+v", res)
	}
	if !exists(victim) {
		t.Fatal("victim gone")
	}
	rd, ok, err := LoadReceipt(te.e, u.Key)
	present, absent := splitReceipt(rd)
	if err != nil || !ok || rd.Gen != 1 || len(present) != 1 || present[0].FromGen != 1 {
		t.Fatalf("receipt %+v %v %v", rd, ok, err)
	}
	// D85: the files the seal deleted stay in the receipt as absent.
	if len(absent) != len(u.Files)-1 {
		t.Fatalf("absent entries %d, want %d", len(absent), len(u.Files)-1)
	}
	// A restore now is a no-op for the file left behind (equal hash).
	rep, err = te.run().restore(ctx, te.keys, RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: u.Key}}})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	// Seal everything again: identical plaintext, no new generation.
	te.fs.inject("unlink", victim, nil)
	rep, _ = te.run().sealCommand(ctx, []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutUnchanged {
		t.Fatalf("retry %+v", res)
	}
	if exists(victim) || len(te.logged(u.Key)) != 1 {
		t.Fatalf("victim left %v, %d generations", exists(victim), len(te.logged(u.Key)))
	}
}

// SEAL-12 and SPEC §17: a full disk aborts, keeps plaintext and leaves no
// temporary.
func TestNoSpaceKeepsPlaintext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		set  func(te *testEnv)
	}{
		{"floor", func(te *testEnv) { te.fs.free = 10 }},
		{"temporary", func(te *testEnv) { te.codec.tmpErr = &os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			tc.set(te)
			rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
			mustNoErr(t, err)
			res := outcome(t, rep, u.Key)
			if res.Outcome != OutFailed || res.Class != fsx.ClassNoSpace {
				t.Fatalf("result %+v", res)
			}
			if !errors.Is(rep.Err(), ErrNoSpace) {
				t.Fatalf("Err = %v", rep.Err())
			}
			for _, f := range te.sessionFiles(u) {
				if !exists(f) {
					t.Fatalf("plaintext lost: %s", f)
				}
			}
			dir := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key)
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Fatalf("temporaries left: %v", ents)
			}
		})
	}
}

// SEAL-13: the generation counter, never the clock, orders generations.
func TestGenerationsIgnoreTheWallClock(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	ctx := tctx(t)
	u := te.scanSession(sid1)
	te.run().sealCommand(ctx, []harness.Unit{u}, Options{})
	te.h.Clock.StepWall(-2 * time.Hour)
	te.writeSession(sid1, "", func(s *claudetest.Session) { s.Lines = 20 })
	u = te.scanSession(sid1)
	rep, _ := te.run().sealCommand(ctx, []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Gen != 2 {
		t.Fatalf("second seal %+v", res)
	}
	gens, err := Generations(te.e, u.Key)
	if err != nil || len(gens) != 2 || gens[0].Gen != 1 || gens[1].Gen != 2 || gens[1].Parent != 1 {
		t.Fatalf("generations %+v %v", gens, err)
	}
	if !gens[1].SealedAt.Before(gens[0].SealedAt) {
		t.Fatalf("clock step not observed: %v %v", gens[0].SealedAt, gens[1].SealedAt)
	}
	p, _ := newestEntry(te.logged(u.Key))
	if p.Gen != 2 {
		t.Fatal("newest is not the highest generation")
	}
}

func TestNextGenNeverReusesANumber(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	key := te.sessionKey(sid1)
	var got []uint64
	for i := 0; i < 3; i++ {
		n, err := NextGen(te.e, key)
		mustNoErr(t, err)
		got = append(got, n)
	}
	if got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("gens %v", got)
	}
	// A lost counter file must not make numbers repeat: the log decides.
	mustNoErr(t, te.e.Log.Append(logEntryFor(key, 7)))
	mustNoErr(t, os.Remove(filepath.Join(te.h.Layout.GensDir, key)))
	n, err := NextGen(te.e, key)
	mustNoErr(t, err)
	if n != 8 {
		t.Fatalf("after losing the counter: %d, want 8", n)
	}
	if _, err := NextGen(te.e, "../escape"); err == nil {
		t.Fatal("invalid unit key accepted")
	}
}

// SEAL-10: an append after the unlink is captured by a rescue generation.
func TestRescueCapturesALateAppend(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	var transcript string
	for _, f := range u.Files {
		if f.Last {
			transcript = filepath.Join(u.Home.Bases[f.Base], f.Rel)
		}
	}
	w, err := os.OpenFile(transcript, os.O_WRONLY|os.O_APPEND, 0)
	mustNoErr(t, err)
	defer w.Close()
	late := `{"uuid":"00000000-0000-4000-8000-00000000eeee","parentUuid":null}` + "\n"
	te.p.sleep = func(ctx context.Context, d time.Duration) error {
		if d == te.p.rescueWait {
			_, _ = w.WriteString(late) // the writer still had the file open
		}
		return nil
	}
	ctx := tctx(t)
	rep, err := te.run().sealCommand(ctx, []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutSealed || res.Gen != 2 {
		t.Fatalf("result %+v", res)
	}
	en := te.logged(u.Key)
	if len(en) != 2 || en[1].Parent != 1 || capsule.Lineage(en[1].Lineage) != capsule.LineagePartial {
		t.Fatalf("rescue generation %+v", en)
	}
	rep, err = te.run().restore(ctx, te.keys, RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: u.Key}}})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	if !strings.HasSuffix(string(readFile(t, transcript)), late) {
		t.Fatal("late append not restored")
	}
	for _, f := range u.Files {
		if !exists(filepath.Join(u.Home.Bases[f.Base], f.Rel)) {
			t.Fatalf("%s missing after the layered restore", f.Rel)
		}
	}
}

// SEAL-15: ledger events appended after the snapshot stay for the next
// generation; Archive gets the snapshot length.
func TestLedgerSnapshotLengthIsArchived(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	k := "claude-code/" + sid1
	te.ledger.raw[k] = []byte(`{"v":1,"type":"start"}` + "\n")
	n := int64(len(te.ledger.raw[k]))
	te.codec.betweenPasses = func() {
		te.ledger.mu.Lock()
		te.ledger.raw[k] = append(te.ledger.raw[k], []byte(`{"v":1,"type":"end"}`+"\n")...)
		te.ledger.mu.Unlock()
	}
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("result %+v", res)
	}
	if te.ledger.archived[k] != n {
		t.Fatalf("archived %d, want the snapshot length %d", te.ledger.archived[k], n)
	}
	if string(te.ledger.raw[k]) != `{"v":1,"type":"end"}`+"\n" {
		t.Fatalf("events after the snapshot lost: %q", te.ledger.raw[k])
	}
}

// CONC-1 (bounded parallelism) and R19: at most Parallel seals at once; a
// big unit runs alone.
func TestSealParallelismIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow (fsync-heavy): skipped with -short")
	}
	te := newTestEnv(t)
	var sids []string
	for i := 0; i < 6; i++ {
		sid := "00000000-0000-4000-8000-0000000000b" + itoa(i)
		te.writeSession(sid, "", nil)
		sids = append(sids, sid)
	}
	var mu sync.Mutex
	cur, peak := 0, 0
	te.codec.betweenPasses = func() {
		mu.Lock()
		cur++
		if cur > peak {
			peak = cur
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		cur--
		mu.Unlock()
	}
	var units []harness.Unit
	for _, sid := range sids {
		units = append(units, te.scanSession(sid))
	}
	rep, _ := te.run().sealCommand(tctx(t), units, Options{})
	if rep.Count(OutSealed) != 6 {
		t.Fatalf("sealed %d of 6: %+v", rep.Count(OutSealed), rep.Units)
	}
	if peak > 2 {
		t.Fatalf("%d seals ran at once, want ≤ 2", peak)
	}
	old := bigUnit
	bigUnit = 1
	defer func() { bigUnit = old }()
	peak = 0
	for i := 0; i < 3; i++ {
		sid := "00000000-0000-4000-8000-0000000000c" + itoa(i)
		te.writeSession(sid, "", nil)
		units = append(units[:0], te.scanSession(sid))
	}
	var big []harness.Unit
	for i := 0; i < 3; i++ {
		big = append(big, te.scanSession("00000000-0000-4000-8000-0000000000c"+itoa(i)))
	}
	te.run().sealCommand(tctx(t), big, Options{})
	if peak != 1 {
		t.Fatalf("big units ran %d at once, want alone", peak)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	before := snapshotTree(t, te.h.Dir)
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{DryRun: true})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || res.Detail != "dry-run" {
		t.Fatalf("result %+v", res)
	}
	after := snapshotTree(t, te.h.Dir)
	for p, h := range before {
		if after[p] != h {
			t.Fatalf("%s changed", p)
		}
	}
	if len(te.logged(u.Key)) != 0 {
		t.Fatal("logged in a dry run")
	}
}

func TestSealWaitsForTheWriterToExit(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	te.h.Procs.Add(procInfo(4242, 99))
	waits := 0
	te.p.sleep = func(ctx context.Context, d time.Duration) error {
		waits++
		if waits == 3 {
			te.h.Procs.Exit(4242, true) // a zombie counts as exited
		}
		return nil
	}
	id := procInfo(4242, 99).ID
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{WaitFor: &id})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || waits < 3 {
		t.Fatalf("result %+v after %d waits", res, waits)
	}
	// With a deadline already passed the writer is still running: live.
	te.writeSession(sid2, "", nil)
	te.h.Procs.Add(procInfo(4343, 7))
	id2 := procInfo(4343, 7).ID
	te.p.sleep = func(ctx context.Context, d time.Duration) error {
		te.h.Clock.Advance(time.Second)
		return nil
	}
	u2 := te.scanSession(sid2)
	rep, _ = te.run().sealCommand(tctx(t), []harness.Unit{u2}, Options{WaitFor: &id2, Deadline: te.h.Clock.Now().Add(500 * time.Millisecond)})
	if res := outcome(t, rep, u2.Key); res.Outcome != OutLive {
		t.Fatalf("deadline result %+v", res)
	}
}

// CC-19: Unit.Prune lists "<base id>:<rel>" entries only: a directory is
// pruned only under the base its entry names (the same rel under another
// base stays), a listed directory that still holds a foreign file stays,
// and a bare rel is ignored and reported.
func TestPruneOnlyListedBaseDirectories(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	cc, tmp := te.h.ClaudeConfig, te.h.ClaudeTmp
	for _, p := range []string{
		filepath.Join(cc, "x", sid1, "a.txt"), filepath.Join(tmp, "x", sid1, "a.txt"),
		filepath.Join(tmp, "keep", sid1, "b.txt"),
	} {
		writeAt(t, p, []byte("unit file\n"))
	}
	writeAt(t, filepath.Join(tmp, "keep", "foreign.txt"), []byte("not ours\n"))
	key := te.sessionKey(sid1)
	u := harness.Unit{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: key, UnitID: sid1, VaultID: rootID,
		RootIDs: []string{rootID}, Home: te.cc, Mode: harness.GenLayered,
		Prune: []string{"claude_tmp:x/" + sid1, "claude_tmp:keep/" + sid1, "claude_tmp:keep", "x/" + sid1}}
	for _, f := range []struct {
		base capsule.BaseID
		rel  string
	}{{capsule.BaseClaudeConfig, "x/" + sid1 + "/a.txt"}, {capsule.BaseClaudeTmp, "x/" + sid1 + "/a.txt"}, {capsule.BaseClaudeTmp, "keep/" + sid1 + "/b.txt"}} {
		st, err := fsx.Lstat(filepath.Join(te.cc.Bases[f.base], filepath.FromSlash(f.rel)))
		mustNoErr(t, err)
		u.Files = append(u.Files, harness.File{Base: f.base, Rel: f.rel, Snap: st, Placement: harness.PlaceExact})
	}
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	res := outcome(t, rep, key)
	if res.Outcome != OutSealed || res.Detail != "1 prune entry without a known base ignored" {
		t.Fatalf("result %+v", res)
	}
	if exists(filepath.Join(tmp, "x", sid1)) || exists(filepath.Join(tmp, "keep", sid1)) {
		t.Fatal("a listed, emptied directory was kept")
	}
	if !exists(filepath.Join(cc, "x", sid1)) {
		t.Fatal("a directory under a base its entry does not name was pruned (bare rel)")
	}
	if !exists(filepath.Join(tmp, "keep", "foreign.txt")) {
		t.Fatal("a listed directory holding a foreign file was removed")
	}
}

// splitReceipt separates a receipt's present and absent (D85) entries.
func splitReceipt(rd Receipt) (present, absent []ReceiptFile) {
	for _, f := range rd.Files {
		if f.Absent {
			absent = append(absent, f)
		} else {
			present = append(present, f)
		}
	}
	return present, absent
}
