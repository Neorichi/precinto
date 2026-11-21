package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

func testBackend(t *testing.T) (*env, *backend) {
	e := newEnv(t)
	a := e.app()
	return e, newBackend(a, e.eng)
}

func TestBackendPlanSeesChildEnv(t *testing.T) {
	e, b := testBackend(t)
	e.eng.plan = harness.LaunchPlan{Mode: harness.LaunchInteractive}
	p, err := b.Plan(context.Background(), harness.ClaudeCode, e.h.Root, []string{"claude"})
	if err != nil || p.Harness != harness.ClaudeCode {
		t.Fatalf("plan %+v err %v", p, err)
	}
	if got := e.eng.planHost[0].Get("CLAUDE_CONFIG_DIR"); got != e.h.ClaudeConfig {
		t.Fatalf("adapter saw CLAUDE_CONFIG_DIR %q, want the child's %q", got, e.h.ClaudeConfig)
	}
}

// SPEC §9.3: the lease is taken before any restore, and every unit a
// restore places is added to it first (BeforePlace).
func TestBackendLeaseAndRestoreSync(t *testing.T) {
	e, b := testBackend(t)
	plan := harness.LaunchPlan{
		Harness: harness.ClaudeCode,
		Roots:   []config.Root{{ID: "root-acme", Path: e.h.Root}},
		Lease:   []string{"codexhomekey"},
		Sync:    []harness.Selector{{Kind: capsule.KindClaudeSession, Keys: []string{"k1"}}},
	}
	ctx := context.Background()
	if _, err := b.AcquireLease(ctx, plan); err != nil {
		t.Fatal(err)
	}
	e.eng.restoreFn = func(keys sweep.KeySource, r sweep.RestoreRequest) {
		if r.BeforePlace == nil {
			t.Error("no BeforePlace")
			return
		}
		if err := r.BeforePlace("k1"); err != nil {
			t.Error(err)
		}
	}
	e.eng.restoreRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutRestored, Files: 2, Bytes: 30}}}
	sum, err := b.RestoreSync(ctx, plan, make(chan struct{}))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Units != 1 || sum.Files != 2 || sum.Bytes != 30 {
		t.Fatalf("summary %+v", sum)
	}
	if got := strings.Join(e.eng.lease.keys, ","); got != "codexhomekey,k1" {
		t.Fatalf("lease keys %q", got)
	}
	r := e.eng.restores[0]
	if r.Purpose != ipc.PurposeRestore || !r.StopOnErr || r.Abort == nil {
		t.Fatalf("restore request %+v", r)
	}
	if ls := e.eng.leaseKeys[0]; len(ls) != 1 || ls[0] != "codexhomekey" {
		t.Fatalf("lease acquired with %v", ls)
	}
}

// Without a lease nothing may be placed.
func TestBackendBeforePlaceWithoutLease(t *testing.T) {
	_, b := testBackend(t)
	if err := b.beforePlace("k"); err == nil {
		t.Fatal("placed without a lease")
	}
}

// An explicit resume of an old session (mtime clamp, D14) prints C7.old.
func TestBackendResumeOldNotice(t *testing.T) {
	e, b := testBackend(t)
	plan := harness.LaunchPlan{Sync: []harness.Selector{{Kind: capsule.KindClaudeSession, MtimeNow: true}}}
	b.AcquireLease(context.Background(), plan)
	e.eng.restoreRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutRestored}}}
	sum, err := b.RestoreSync(context.Background(), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Notices) != 1 || sum.Notices[0] != ui.Format(ui.MsgResumeOld, ui.Vars{Days: 30}) {
		t.Fatalf("notices %q", sum.Notices)
	}
	if !e.eng.restores[0].MtimeNow {
		t.Fatal("MtimeNow not passed")
	}
}

// REST-8: closing abort destroys the file keys at once.
func TestBackendAbortDestroysKeys(t *testing.T) {
	e, b := testBackend(t)
	k := &fakeKeys{}
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		return k, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: "p"}}}, nil
	}
	abort := make(chan struct{})
	plan := harness.LaunchPlan{Sync: []harness.Selector{{Kind: capsule.KindClaudeSession}}}
	b.AcquireLease(context.Background(), plan)
	e.eng.restoreFn = func(keys sweep.KeySource, r sweep.RestoreRequest) {
		if _, err := keys.FileKeys(context.Background(), []string{"p"}, r.Purpose); err != nil {
			t.Error(err)
		}
		close(abort)
		deadline := time.Now().Add(2 * time.Second)
		for !k.isDestroyed() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	b.RestoreSync(context.Background(), plan, abort)
	if !k.isDestroyed() {
		t.Fatal("keys not destroyed within 2 s of the lock")
	}
}

// RecordLaunch writes one ledger launch event per lease key for a known
// sid, and nothing when the sid is not known before exec.
func TestBackendRecordLaunch(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme"}}, Lease: []string{"k1", "k2"},
		Resume: harness.Resume{Kind: harness.ResumeSID, Value: "00000000-0000-4000-8000-000000000001"}}
	b.Plan(ctx, harness.ClaudeCode, e.h.Root, []string{"claude"})
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	if len(e.eng.ledgerEvs) != 2 {
		t.Fatalf("events %+v", e.eng.ledgerEvs)
	}
	ev := e.eng.ledgerEvs[0]
	if ev.Type != ledger.TypeLaunch || ev.SID != plan.Resume.Value || ev.Proc != child || !ev.Wrapper || ev.Cwd != e.h.Root ||
		ev.LeaseKey != "k1" || ev.ConfigDir != e.h.ClaudeConfig || len(ev.Roots) != 1 {
		t.Fatalf("event %+v", ev)
	}
	e.eng.ledgerEvs = nil
	plan.Resume = harness.Resume{Kind: harness.ResumePicker}
	if err := b.RecordLaunch(ctx, plan, child); err != nil || len(e.eng.ledgerEvs) != 0 {
		t.Fatalf("picker launch wrote %+v (%v)", e.eng.ledgerEvs, err)
	}
	// A transcript path names the sid by its basename.
	plan.Resume = harness.Resume{Kind: harness.ResumePath, Value: "/x/00000000-0000-4000-8000-000000000002.jsonl"}
	b.RecordLaunch(ctx, plan, child)
	if len(e.eng.ledgerEvs) == 0 || e.eng.ledgerEvs[0].SID != "00000000-0000-4000-8000-000000000002" {
		t.Fatalf("events %+v", e.eng.ledgerEvs)
	}
}

// SealAfterExit: sealed units are summarized; a unit still live is queued
// with a detached `seal --queue` worker (MsgSealDeferred).
func TestBackendSealAfterExit(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, SealScope: harness.Scope{SIDs: []string{"sid1"}}}
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutSealed, Files: 3, Bytes: 100}}}
	sum, err := b.SealAfterExit(ctx, plan, child)
	if err != nil || sum.Deferred || sum.Files != 3 || sum.Bytes != 100 || sum.SID != "sid1" {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	o := e.eng.sealOpts[0]
	if o.WaitFor == nil || *o.WaitFor != child || o.Reason != "wrapper-exit" {
		t.Fatalf("seal options %+v", o)
	}
	if s := e.eng.sealScope[0]; len(s.SIDs) != 1 || s.SIDs[0] != "sid1" || len(s.Procs) != 1 || s.Procs[0] != child {
		t.Fatalf("scope %+v, want the plan's sid narrowed to the child (CC-21)", s)
	}

	e, b = testBackend(t)
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutLive}}}
	sum, err = b.SealAfterExit(ctx, plan, child)
	if err != nil || !sum.Deferred {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if len(e.eng.enqueued) != 1 || e.eng.enqueued[0].WaitFor != child || e.eng.enqueued[0].Reason != "wrapper-exit" {
		t.Fatalf("queued %+v", e.eng.enqueued)
	}
	if len(e.spawned) != 1 || strings.Join(e.spawned[0][1:], " ") != "seal --queue" {
		t.Fatalf("spawned %v", e.spawned)
	}

	e, b = testBackend(t)
	e.eng.sealErr = sweep.ErrTripwire
	sum, _ = b.SealAfterExit(ctx, plan, child)
	if sum.Failed != "vault changed outside precinto" {
		t.Fatalf("failed %q", sum.Failed)
	}
}

// EnsureUnlocked unlocks only the locked folders; several need the typed
// "unlock" (D40).
func TestBackendEnsureUnlocked(t *testing.T) {
	e, b := testBackend(t)
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	ctx := context.Background()
	roots := []config.Root{{ID: "root-acme", Path: e.h.Root}, {ID: "root-b", Path: e.h.HomeDir + "/b"}}
	if err := b.EnsureUnlocked(ctx, roots[:1], e.tty); err != nil || len(e.daemon.unlocks) != 0 {
		t.Fatalf("unlocked an unlocked folder: %v %v", e.daemon.unlocks, err)
	}
	if err := b.EnsureUnlocked(ctx, roots, e.tty); err != nil {
		t.Fatal(err)
	}
	if r := e.daemon.unlocks[0]; len(r.RootIDs) != 1 || r.RootIDs[0] != "root-b" || !r.Confirmed || !r.TTY {
		t.Fatalf("request %+v", r)
	}
	e.daemon.status = ipc.StatusResp{}
	e.tty.confirms = []bool{false}
	if err := b.EnsureUnlocked(ctx, roots, e.tty); err == nil {
		t.Fatal("two folders unlocked without confirmation")
	}
	if err := b.EnsureUnlocked(ctx, roots, headlessUI{}); err == nil {
		t.Fatal("two folders unlocked without a terminal")
	}
}

func TestBackendDaemonAutostarts(t *testing.T) {
	e, b := testBackend(t)
	d, err := b.Daemon(context.Background())
	if err != nil || d == nil || !e.dials[0].Autostart {
		t.Fatalf("daemon %v err %v dials %+v", d, err, e.dials)
	}
}

func TestBackendHomeOfCodex(t *testing.T) {
	_, b := testBackend(t)
	plan := harness.LaunchPlan{Harness: harness.Codex, Env: []string{"TMPDIR=/x", "CODEX_HOME=/base/homes/codex/root-acme"}}
	if got := b.homeOf(plan); got != "/base/homes/codex/root-acme" {
		t.Fatalf("home %q", got)
	}
}

// An empty seal scope would mean "every folder": SealAfterExit narrows it to
// the child's own sessions (Scope.Procs) and never widens it to the plan's
// folders (CC-21, R4); an unmanaged launch seals nothing.
func TestBackendSealScopeNeverWidens(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1, StartUS: 2}
	if _, err := b.SealAfterExit(ctx, harness.LaunchPlan{Harness: harness.ClaudeCode}, child); err != nil {
		t.Fatal(err)
	}
	if e.eng.called("Seal") {
		t.Fatal("an unmanaged launch sealed something")
	}
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme"}}}
	if _, err := b.SealAfterExit(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	if s := e.eng.sealScope[0]; len(s.RootIDs) != 0 || len(s.SIDs) != 0 || len(s.Procs) != 1 || s.Procs[0] != child {
		t.Fatalf("scope %+v, want only the child's sessions", s)
	}
}
