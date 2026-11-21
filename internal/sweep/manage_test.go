package sweep

import (
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
	mustNoErr(t, r.quarantine(context.Background()))
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
	if err := te.run().quarantine(context.Background()); err == nil {
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	rep, err := te.run().sweep(context.Background(), Options{})
	mustNoErr(t, err)
	if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped || !strings.HasPrefix(res.Detail, "restored") {
		t.Fatalf("unlocked folder %+v", res)
	}
	// Grants failing means every folder is locked (R4).
	te.e.Grants = func(context.Context) (map[string]bool, error) { return nil, errors.New("daemon unreachable") }
	rep, err = te.run().sweep(context.Background(), Options{})
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
	rep, err := te.run().sweep(context.Background(), Options{})
	if !errors.Is(err, ErrBusy) || rep == nil {
		t.Fatalf("sweep while locked: %v", err)
	}
	if !exists(te.h.Layout.SweepRequested) {
		t.Fatal("sweep.requested not touched")
	}
	lk.Unlock()
	// The holder rescans once and consumes the request.
	te.writeSession(sid1, "", nil)
	rep, err = te.run().sweep(context.Background(), Options{})
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
	rep, err := te.run().sweep(context.Background(), Options{})
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
	r.drainQueue(context.Background(), Options{})
	if len(r.finish().Units) != 0 || !exists(transcriptOf(u)) {
		t.Fatal("sealed while the writer runs (R8)")
	}
	te.h.Procs.Exit(5150, false)
	te.live.set(u.Key, live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnstable, Weak: true}}})
	r = te.run()
	r.drainQueue(context.Background(), Options{})
	reqs, _ := queue.List(te.h.Layout.QueueDir)
	if len(reqs) != 1 || reqs[0].Attempts != 1 || !reqs[0].NotBefore.After(te.h.Clock.Now()) {
		t.Fatalf("live unit not backed off: %+v", reqs)
	}
	te.live.set(u.Key, live.Verdict{})
	delete(te.live.verdicts, u.Key)
	te.h.Clock.Advance(time.Hour)
	r = te.run()
	r.drainQueue(context.Background(), Options{})
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
	r.drainQueue(context.Background(), Options{})
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
	infos, err := te.run().list(context.Background(), ListOptions{RootIDs: []string{rootID}})
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
	infos, _ = te.run().list(context.Background(), ListOptions{Keys: te.keys})
	for _, i := range infos {
		if i.Unit == u.Key && i.Title != "title of "+sid1 {
			t.Fatalf("title %q", i.Title)
		}
	}
	if te.keys.purposes[len(te.keys.purposes)-1] != "list" {
		t.Fatalf("purposes %v", te.keys.purposes)
	}
	sum, err := te.run().plaintextSummary(context.Background())
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
