package sweep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
)

// SEC-1: a forged capsule (valid format, no log entry) planted in the
// store is quarantined and never restored.
func TestQuarantineMovesUnloggedCapsules(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	key2 := te.sessionKey(sid2)
	man := capsule.Manifest{Format: 1, Kind: capsule.KindClaudeSession, Harness: "claude-code", UnitKey: key2, UnitID: sid2,
		VaultID: rootID, RootIDs: []string{rootID}, Gen: 1}
	te.forge(key2, man, map[string][]byte{"projects/p/" + sid2 + ".jsonl": []byte("{}\n")}, 1)
	// Drop the forged capsule's log line: it now has no provenance.
	all := te.allLogged()
	var keep []byte
	for _, en := range all {
		if en.Unit != key2 {
			b, _ := jsonLine(en)
			keep = append(keep, b...)
		}
	}
	mustNoErr(t, os.WriteFile(te.h.Layout.CapsuleLog, keep, 0o600))
	stray := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "evil.pcap")
	writeAt(t, stray, []byte("not even a capsule"))
	r := te.run()
	mustNoErr(t, r.quarantine(tctx(t)))
	rep := r.finish()
	if rep.Count(OutQuarantined) != 2 {
		t.Fatalf("quarantined %+v", rep.Units)
	}
	if exists(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", key2, "g000001.pcap")) || exists(stray) {
		t.Fatal("unlogged capsules left in the store")
	}
	q, _ := filepath.Glob(filepath.Join(te.h.Layout.QuarantineDir, "*", "claude-code", key2, "g000001.pcap"))
	if len(q) != 1 {
		t.Fatalf("not in quarantine: %v", q)
	}
	// The logged capsule stays, and List shows the quarantined unit.
	if !exists(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")) {
		t.Fatal("a logged capsule was quarantined")
	}
	if !te.run().quarantinedUnits()[key2] {
		t.Fatal("quarantined unit not listed")
	}
	// An unreadable journal record makes quarantine refuse entirely.
	writeAt(t, filepath.Join(te.h.Layout.JournalDir, "0000000000000001-00000000.json"), []byte("{"))
	writeAt(t, filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000009.pcap"), []byte("x"))
	if err := te.run().quarantine(tctx(t)); err == nil {
		t.Fatal("quarantine ran with an unreadable journal")
	}
}

func jsonLine(en capslog.Entry) ([]byte, error) {
	b, err := json.Marshal(en)
	return append(b, '\n'), err
}

// keepSet is retention (D9, D15, D42).
func TestKeepSet(t *testing.T) {
	t.Parallel()
	e := func(gen, parent uint64, l capsule.Lineage) capslog.Entry {
		return capslog.Entry{Gen: gen, Parent: parent, Lineage: string(l)}
	}
	chainOf := []capslog.Entry{
		e(1, 0, capsule.LineageFresh), e(2, 1, capsule.LineageSuccessor), e(3, 2, capsule.LineageDiverged),
		e(4, 3, capsule.LineageSuccessor), e(5, 4, capsule.LineageSuccessor), e(6, 5, capsule.LineagePartial),
		e(7, 6, capsule.LineageSuccessor),
	}
	got := keepSet(chainOf, 3, false, nil, false)
	for _, g := range []uint64{5, 6, 7, 3} {
		if !got[g] {
			t.Errorf("generation %d pruned", g)
		}
	}
	for _, g := range []uint64{1, 2, 4} {
		if got[g] {
			t.Errorf("generation %d kept", g)
		}
	}
	if keepSet(chainOf, 3, true, nil, false)[3] {
		t.Error("--diverged did not prune the diverged generation")
	}
	// The layered chain of the newest is always kept.
	partial := []capslog.Entry{e(1, 0, capsule.LineageFresh), e(2, 1, capsule.LineageSuccessor), e(3, 2, capsule.LineagePartial),
		e(4, 3, capsule.LineagePartial), e(5, 4, capsule.LineagePartial)}
	if got := keepSet(partial, 1, true, nil, false); !got[2] || !got[3] || !got[4] || got[1] {
		t.Errorf("layered chain not kept: %v", got)
	}
	// Receipts pin their generations (CONC-3).
	rd := &receiptDisk{Receipt: Receipt{Gen: 2, Files: []ReceiptFile{{FromGen: 1}}}}
	if got := keepSet(chainOf, 1, true, rd, false); !got[1] || !got[2] {
		t.Errorf("receipt generations pruned: %v", got)
	}
}

func TestPruneAndForget(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("slow (fsync-heavy): skipped with -short")
	}
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	ctx := tctx(t)
	for i := 0; i < 4; i++ {
		te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
		appendLines(t, transcriptOf(u), `{"uuid":"00000000-0000-4000-8000-0000000001`+itoa(i)+`0"}`)
		te.run().sealCommand(ctx, []harness.Unit{te.scanSession(sid1)}, Options{})
	}
	if n := len(te.logged(u.Key)); n != 5 {
		t.Fatalf("%d generations", n)
	}
	rep, err := te.run().prune(ctx, PruneOptions{Unit: u.Key, DryRun: true})
	mustNoErr(t, err)
	if last := rep.Units[len(rep.Units)-1]; len(te.logged(u.Key)) != 5 || last.Outcome != OutPruned || last.Files != 2 || !strings.HasPrefix(last.Detail, "dry-run") {
		t.Fatalf("dry run deleted: %+v", rep.Units)
	}
	rep, err = te.run().prune(ctx, PruneOptions{Unit: u.Key})
	mustNoErr(t, err)
	if rep.Count(OutPruned) != 1 || rep.Count(OutSkipped) != 0 {
		t.Fatalf("prune outcomes %+v (CC-30: OutPruned, not OutSkipped)", rep.Units)
	}
	gens := te.logged(u.Key)
	if len(gens) != 3 || gens[0].Gen != 3 {
		t.Fatalf("after prune %+v", gens)
	}
	if exists(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")) {
		t.Fatal("pruned capsule file left")
	}
	// The newest still restores completely.
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if !exists(transcriptOf(u)) {
		t.Fatal("restore after prune")
	}
	// Forget deletes every generation, logs the deletions, drops the receipt.
	if _, err := Forget(ctx, te.e, "not-a-key"); err != nil {
		t.Fatal(err)
	}
	r := te.run()
	r.recoverAll(ctx)
	rep2, err := forgetWith(te, u.Key)
	mustNoErr(t, err)
	if len(te.logged(u.Key)) != 0 || rep2.Count(OutForgotten) != 1 || rep2.Count(OutSkipped) != 0 {
		t.Fatalf("forget %+v", rep2.Units)
	}
	if _, ok, _ := LoadReceipt(te.e, u.Key); ok {
		t.Fatal("receipt left after forget")
	}
	b := readFile(t, te.h.Layout.CapsuleLog)
	if !strings.Contains(string(b), `"deleted":true`) {
		t.Fatal("deletion records not logged")
	}
}

// forgetWith runs Forget's logic with the test ports.
func forgetWith(te *testEnv, unit string) (*Report, error) {
	r := te.run()
	res := UnitResult{Unit: unit}
	lk, err := r.lockUnit(unit)
	if err != nil {
		return nil, err
	}
	defer lk.Unlock()
	entries, _ := r.log.Unit(unit)
	var del []string
	var gens []uint64
	for _, en := range entries {
		del = append(del, en.Path)
		gens = append(gens, en.Gen)
	}
	if err := r.deleteCapsules(unit, "claude-code", del, gens); err != nil {
		return nil, err
	}
	_ = r.deleteReceipt(unit)
	res.Outcome, res.Files = OutForgotten, len(del) // as Forget reports it (CC-30)
	r.add(res)
	return r.finish(), nil
}

// CONC-3: prune never deletes a generation a receipt references.
func TestPruneKeepsReceiptGenerations(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("slow (fsync-heavy): skipped with -short")
	}
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	ctx := tctx(t)
	for i := 0; i < 3; i++ {
		te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
		appendLines(t, transcriptOf(u), `{"uuid":"00000000-0000-4000-8000-0000000002`+itoa(i)+`0"}`)
		te.run().sealCommand(ctx, []harness.Unit{te.scanSession(sid1)}, Options{})
	}
	// A receipt pointing at generation 1 (an old restore still on disk).
	mustNoErr(t, te.run().writeReceipt(receiptDisk{Receipt: Receipt{Unit: u.Key, Gen: 1, Files: []ReceiptFile{{Base: capsule.BaseClaudeConfig, Rel: "x", FromGen: 1}}}}))
	te.run().prune(ctx, PruneOptions{Unit: u.Key, KeepLast: 1})
	have := map[uint64]bool{}
	for _, en := range te.logged(u.Key) {
		have[en.Gen] = true
	}
	if !have[1] || !have[4] {
		t.Fatalf("receipt or newest generation pruned: %v", have)
	}
}

// Sweep seals only units of locked folders, honours liveness, takes the
// sweep lock and rescans once when asked meanwhile.
func TestSweepSealsLockedFoldersOnly(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	te.e.Grants = func(context.Context) (map[string]bool, error) { return map[string]bool{rootID: true}, nil }
	rep, err := te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped || !strings.HasPrefix(res.Detail, "restored") {
		t.Fatalf("unlocked folder %+v", res)
	}
	// Grants failing means every folder is locked (R4).
	te.e.Grants = func(context.Context) (map[string]bool, error) { return nil, errors.New("daemon unreachable") }
	rep, err = te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("locked folder %+v", res)
	}
	if !exists(te.h.Layout.SweepLast) {
		t.Fatal("no sweep heartbeat")
	}
}

func TestSweepBusyTouchesRequested(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	lk, err := te.run().lockName("sweep")
	mustNoErr(t, err)
	rep, err := te.run().sweep(tctx(t), Options{})
	if !errors.Is(err, ErrBusy) || rep == nil {
		t.Fatalf("sweep while locked: %v", err)
	}
	if !exists(te.h.Layout.SweepRequested) {
		t.Fatal("sweep.requested not touched")
	}
	lk.Unlock()
	// The holder rescans once and consumes the request.
	te.writeSession(sid1, "", nil)
	rep, err = te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if exists(te.h.Layout.SweepRequested) {
		t.Fatal("request not consumed")
	}
	if rep.Count(OutSealed) != 1 {
		t.Fatalf("sweep %+v", rep.Units)
	}
}

// REST-7: a sweep right after a restore with the lease present seals
// nothing.
func TestSweepHonoursLeases(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	te.live.set(u.Key, live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonLease}}})
	rep, err := te.run().sweep(tctx(t), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutLeased {
		t.Fatalf("result %+v", res)
	}
	if !exists(transcriptOf(u)) {
		t.Fatal("I1: leased unit sealed")
	}
	if rep.Err() != nil {
		t.Fatalf("a sweep reports a live unit as a failure: %v", rep.Err())
	}
}

// SPEC §10.6: queued requests wait for their writer, then seal; live
// units back off; a full disk backs off ≥ 60 s.
func TestDrainQueue(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	writer := procInfo(5150, 1)
	te.h.Procs.Add(writer)
	id, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sid1, Reason: "prompt_input_exit", WaitFor: writer.ID})
	mustNoErr(t, err)
	r := te.run()
	r.drainQueue(tctx(t), Options{})
	if len(r.finish().Units) != 0 || !exists(transcriptOf(u)) {
		t.Fatal("sealed while the writer runs (R8)")
	}
	te.h.Procs.Exit(5150, false)
	te.live.set(u.Key, live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnstable, Weak: true}}})
	r = te.run()
	r.drainQueue(tctx(t), Options{})
	reqs, _ := queue.List(te.h.Layout.QueueDir)
	if len(reqs) != 1 || reqs[0].Attempts != 1 || !reqs[0].NotBefore.After(te.h.Clock.Now()) {
		t.Fatalf("live unit not backed off: %+v", reqs)
	}
	te.live.set(u.Key, live.Verdict{})
	delete(te.live.verdicts, u.Key)
	te.h.Clock.Advance(time.Hour)
	r = te.run()
	r.drainQueue(tctx(t), Options{})
	if res := outcome(t, r.finish(), u.Key); res.Outcome != OutSealed {
		t.Fatalf("drain %+v", res)
	}
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatalf("request %s left", id)
	}
	if backoff(1, true) < time.Minute || backoff(1, false) >= time.Minute || backoff(40, false) > 30*time.Minute {
		t.Fatal("backoff bounds")
	}
}

func TestDrainQueueGivesUpAtTheDeadline(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "codex", SID: sid1, Reason: "codex-exit",
		Deadline: te.h.Clock.Now().Add(-time.Minute)})
	mustNoErr(t, err)
	r := te.run()
	r.drainQueue(tctx(t), Options{})
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatal("expired request kept")
	}
	if !exists(transcriptOf(te.scanSession(sid1))) {
		t.Fatal("plaintext touched")
	}
}

func TestListAndPlaintextSummary(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.writeSession(sid2, "", nil)
	infos, err := te.run().list(tctx(t), ListOptions{RootIDs: []string{rootID}})
	mustNoErr(t, err)
	got := map[string]UnitInfo{}
	for _, i := range infos {
		got[i.Unit] = i
	}
	if i := got[u.Key]; len(i.Gens) != 1 || i.Plaintext || i.Title != "" {
		t.Fatalf("sealed unit %+v", i)
	}
	if i := got[te.sessionKey(sid2)]; !i.Plaintext || i.Reason != "deferred" {
		t.Fatalf("plaintext unit %+v", i)
	}
	infos, _ = te.run().list(tctx(t), ListOptions{Keys: te.keys})
	for _, i := range infos {
		if i.Unit == u.Key && i.Title != "title of "+sid1 {
			t.Fatalf("title %q", i.Title)
		}
	}
	if te.keys.purposes[len(te.keys.purposes)-1] != "list" {
		t.Fatalf("purposes %v", te.keys.purposes)
	}
	sum, err := te.run().plaintextSummary(tctx(t))
	mustNoErr(t, err)
	if len(sum) != 1 || sum[0].RootID != rootID || sum[0].Files == 0 || sum[0].ByReason["deferred"] == 0 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestReportCountAndErr(t *testing.T) {
	t.Parallel()
	rep := &Report{Units: []UnitResult{
		{Outcome: OutSealed}, {Outcome: OutSealed},
		{Outcome: OutLive, Detail: "registry"},
		{Outcome: OutFailed, Detail: "tripwire: x"},
		{Outcome: OutFailed, Detail: "verify: x"},
		{Outcome: OutLive, Detail: "live: changed"},
		{Outcome: OutInaccessible, Detail: "inaccessible: permission denied"},
		{Outcome: OutFailed, Detail: "failed: error"},
		{Outcome: OutConflict, Detail: "conflict: x"},
	}}
	if rep.Count(OutSealed) != 2 || rep.Count(OutLive) != 2 || (*Report)(nil).Count(OutSealed) != 0 {
		t.Fatal("Count")
	}
	err := rep.Err()
	for _, want := range []error{ErrTripwire, capsule.ErrVerify, ErrLive, ErrInaccessible, ErrConflict} {
		if !errors.Is(err, want) {
			t.Errorf("Err does not wrap %v", want)
		}
	}
	if (&Report{Units: []UnitResult{{Outcome: OutLive, Detail: "registry"}, {Outcome: OutSkipped}}}).Err() != nil {
		t.Error("informational outcomes reported as failures")
	}
	if (*Report)(nil).Err() != nil {
		t.Error("nil report")
	}
	if code, class := failureCode(&os.PathError{Op: "open", Path: "/x", Err: syscall.ENOSPC}); code != codeNoSpace || class != fsx.ClassNoSpace {
		t.Errorf("ENOSPC → %s %s", code, class)
	}
	if code, _ := failureCode(&os.PathError{Op: "open", Path: "/x", Err: syscall.EPERM}); code != codeInaccessible {
		t.Errorf("EPERM → %s", code)
	}
	if msg := safeMsg(&os.PathError{Op: "open", Path: "/Users/someone/secret", Err: syscall.EACCES}); strings.Contains(msg, "/Users") {
		t.Errorf("a path leaked into a detail: %q", msg)
	}
}

func TestProcIDHelpers(t *testing.T) {
	t.Parallel()
	p := procInfo(1, 2)
	if p.ID == (platform.ProcID{}) {
		t.Fatal("zero")
	}
	_ = testkit.Epoch
}

// CC-21: a sweep scoped to processes (Scope.Procs) seals the sessions
// those processes own and nothing else: another session of the folder,
// its notes and the global history stay as they are.
func TestSweepScopedToProcsSealsOnlyTheirSessions(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	child := procInfo(6001, 11).ID
	te.writeSession(sid1, "", nil)
	te.writeSession(sid2, "", nil)
	te.claude.owners = map[string][]platform.ProcID{sid1: {child}, sid2: {procInfo(6002, 12).ID}}
	p := te.note("docs/notes.md", "body\n")
	appendLines(t, te.historyPath(), historyLineFor(te.h.Root, "root", 1, ""))
	u1, u2 := te.scanSession(sid1), te.scanSession(sid2)
	rep, err := te.run().sweep(tctx(t), Options{Scope: harness.Scope{Procs: []platform.ProcID{child}}})
	mustNoErr(t, err)
	if res := outcome(t, rep, u1.Key); res.Outcome != OutSealed {
		t.Fatalf("own session %+v", res)
	}
	for _, u := range rep.Units {
		if u.Unit != u1.Key {
			t.Fatalf("a sweep scoped to the child touched %+v", u)
		}
	}
	if !exists(transcriptOf(u2)) || !exists(p) || len(te.historyLines()) != 1 {
		t.Fatal("another session, a note or the history was sealed")
	}
}

// CC-21: seal --adopt (Options.Adopt) and md = "all" ask the adapters for
// sessions found only by transcript cwd (Scope.Adopt), and seal them.
func TestSweepAsksForAdoptedSessions(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	var asked []bool
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	u.Adopted = true
	te.claude.sids = nil
	te.claude.extra = []harness.Unit{u}
	te.claude.onScan = func(s harness.Scope) { asked = append(asked, s.Adopt) }
	rep, _ := te.run().sweep(tctx(t), Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped || res.Detail != "adopted: seal --adopt" {
		t.Fatalf("plain sweep %+v", res)
	}
	rep, _ = te.run().sweep(tctx(t), Options{Adopt: true})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("--adopt sweep %+v", res)
	}
	if len(asked) < 2 || asked[0] || !asked[len(asked)-1] {
		t.Fatalf("Scope.Adopt per scan %v, want false then true", asked)
	}
}

// FX-G4-10, FX-G4-16, D63: PlaintextSummary and List classify plaintext
// from one look, without new state: strong evidence is running; weak
// evidence the quiet wait never resolves holds a locked folder's unit
// hold-capped; a first observation only is deferred (the next sweep waits
// for it); a restored unit of an unlocked folder is restored, of a locked
// one deferred (D110); a locked folder's plaintext still matching the
// receipt its committed seal kept is remove-failed; an adopted session is
// adopted and a unit below the free-space floor disk_full (D111, D113); an
// unreadable scan entry is inaccessible.
func TestPlaintextReasons(t *testing.T) {
	t.Parallel()
	reasonOf := func(t *testing.T, te *testEnv, key string) string {
		t.Helper()
		sum, err := te.run().plaintextSummary(tctx(t))
		mustNoErr(t, err)
		infos, err := te.run().list(tctx(t), ListOptions{})
		mustNoErr(t, err)
		listed := ""
		for _, i := range infos {
			if i.Unit == key {
				listed = i.Reason
			}
		}
		var reasons []string
		for _, p := range sum {
			for why, n := range p.ByReason {
				if n > 0 && why != "history_pending" && why != "notes" {
					reasons = append(reasons, why)
				}
			}
		}
		if len(reasons) != 1 || reasons[0] != listed {
			t.Fatalf("summary reasons %v, list reason %q", reasons, listed)
		}
		return listed
	}
	unlock := func(te *testEnv) {
		te.e.Grants = func(context.Context) (map[string]bool, error) { return map[string]bool{rootID: true}, nil }
	}
	for _, tc := range []struct {
		name string
		want string
		prep func(t *testing.T, te *testEnv) string
	}{
		{"running", "running", func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			k := te.sessionKey(sid1)
			te.claude.probe[k] = []live.Evidence{{Reason: live.ReasonLedgerProc}}
			return k
		}},
		{"hold-capped", reasonHoldCapped, func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			k := te.sessionKey(sid1)
			te.claude.probe[k] = []live.Evidence{{Reason: live.ReasonRegistry, Weak: true}, {Reason: live.ReasonUnobserved, Weak: true}}
			return k
		}},
		{"weak in an unlocked folder", "running", func(t *testing.T, te *testEnv) string {
			unlock(te)
			te.writeSession(sid1, "", nil)
			k := te.sessionKey(sid1)
			te.claude.probe[k] = []live.Evidence{{Reason: live.ReasonRegistry, Weak: true}}
			return k
		}},
		{"deferred", "deferred", func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			k := te.sessionKey(sid1)
			te.live.set(k, live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnobserved, Weak: true}}})
			return k
		}},
		{"restored", "restored", func(t *testing.T, te *testEnv) string {
			u, _ := te.sealedSession(sid1, nil)
			te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
			unlock(te)
			return u.Key
		}},
		{"remove-failed", "remove-failed", func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			for _, p := range te.sessionFiles(u) {
				te.fs.inject("unlink", p, syscall.EACCES)
			}
			rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
			if res := outcome(t, rep, u.Key); res.Outcome != OutRemoveFailed {
				t.Fatalf("seal %+v", res)
			}
			return u.Key
		}},
		// UX-10, D110: a restore's plaintext in a folder locked since
		// (its session kept it leased past the lock's sweep) waits for
		// the next sweep; it is not an unlink that failed.
		{"restored in a locked folder", "deferred", func(t *testing.T, te *testEnv) string {
			u, _ := te.sealedSession(sid1, nil)
			te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
			return u.Key
		}},
		// UX-11, D111: below the free-space floor now.
		{"disk full", reasonDiskFull, func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			te.fs.mu.Lock()
			te.fs.free = 1 << 10
			te.fs.mu.Unlock()
			return te.sessionKey(sid1)
		}},
		// UX-17, D113: a session found only by its transcripts' cwd, which
		// sweeps leave to seal --adopt.
		{"adopted", reasonAdopted, func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			u.Adopted = true
			te.claude.sids = nil
			te.claude.extra = []harness.Unit{u}
			return u.Key
		}},
		{"inaccessible", "inaccessible", func(t *testing.T, te *testEnv) string {
			te.writeSession(sid1, "", nil)
			u := te.scanSession(sid1)
			u.Hazards = append(u.Hazards, harness.Hazard{Base: capsule.BaseClaudeConfig, Rel: "projects/x", Hazard: fsx.HazardAccess})
			te.claude.sids = nil
			te.claude.extra = []harness.Unit{u}
			return u.Key
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			key := tc.prep(t, te)
			if got := reasonOf(t, te, key); got != tc.want {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

// FX-G4-20: every reader of precinto's own state (receipts, generation
// counters, snapshot refs, the pending-notes index) opens O_NONBLOCK and
// O_NOFOLLOW, requires a regular file and is bounded: a FIFO never blocks
// a run, and the writers replace it.
func TestStateReadersNeverBlockOnAFIFO(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	key := te.sessionKey(sid1)
	r := te.run()
	for _, dir := range []string{te.h.Layout.ReceiptsDir, te.h.Layout.GensDir, filepath.Dir(te.h.Layout.NotesIndex)} {
		mustNoErr(t, ensurePrivateDir(dir))
	}
	fifos := []string{r.receiptPath(key), filepath.Join(te.h.Layout.GensDir, key), r.refsPath(key), te.h.Layout.NotesIndex}
	for _, p := range fifos {
		mustNoErr(t, mkfifo(p))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := r.loadReceipt(key); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("receipt FIFO: %v, want ErrUnsafe", err)
		}
		if n, err := r.nextGen(tctx(t), key, nil); err != nil || n != 1 {
			t.Errorf("counter FIFO: nextGen %d %v, want 1 (read as 0, then replaced)", n, err)
		}
		if refs := r.readRefs(key); len(refs.Gens) != 0 {
			t.Errorf("refs FIFO read as %+v", refs)
		}
		if idx := r.readNotesIndex(); len(idx.Roots) != 0 {
			t.Errorf("notes index FIFO read as %+v", idx)
		}
		r.updateNotesIndex(tctx(t), func(idx *notesIndex) { idx.Roots[rootID] = []string{"/x.md"} })
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a state reader blocked on a FIFO")
	}
	for _, p := range []string{filepath.Join(te.h.Layout.GensDir, key), te.h.Layout.NotesIndex} {
		if st, err := fsx.Lstat(p); err != nil || !st.IsRegular() {
			t.Fatalf("%s not replaced by a regular file", filepath.Base(p))
		}
	}
	if got := r.pendingNotes(rootID); len(got) != 1 {
		t.Fatalf("notes index after the rewrite: %v", got)
	}
	// Bounded: an oversized index reads as empty.
	writeAt(t, te.h.Layout.NotesIndex, bytes.Repeat([]byte(" "), maxNotesIndexBytes+1))
	if idx := r.readNotesIndex(); len(idx.Roots) != 0 {
		t.Fatal("an oversized notes index was read")
	}
}
