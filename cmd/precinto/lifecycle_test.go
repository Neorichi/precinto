package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

// D107: the id PlanLaunch chose for a fresh launch (LaunchPlan.SessionID)
// is recorded like a resume target: one launch event of the child, with
// the plan's folders, so the session is managed without hooks.
func TestBackendRecordLaunchOfAFreshSession(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	const sid = "00000000-0000-4000-8000-0000000000e1"
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme"}},
		SessionID: sid, SealScope: harness.Scope{RootIDs: []string{"root-acme"}}}
	b.Plan(ctx, harness.ClaudeCode, e.h.Root, []string{"claude"})
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	if len(e.eng.ledgerEvs) != 1 {
		t.Fatalf("events %+v", e.eng.ledgerEvs)
	}
	ev := e.eng.ledgerEvs[0]
	if ev.Type != ledger.TypeLaunch || ev.SID != sid || ev.Proc != child || !ev.Wrapper || !slices.Equal(ev.Roots, []string{"root-acme"}) {
		t.Fatalf("event %+v", ev)
	}
}

// D107: WatchSessions records every session the child's registry entry
// names that has no launch event of the child yet. The seal after exit of
// a fresh launch is not narrowed to named sessions: it takes every session
// the child owns (Scope.Procs), whoever recorded it — the launch, the
// watch or the hooks; a resume's scope, which names its target, takes the
// sessions the watch recorded too.
func TestBackendWatchSessionsWidensTheSeal(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	const fresh, cleared = "00000000-0000-4000-8000-0000000000e1", "00000000-0000-4000-8000-0000000000e2"
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}},
		SessionID: fresh, SealScope: harness.Scope{RootIDs: []string{"root-acme"}}}
	b.Plan(ctx, harness.ClaudeCode, e.h.Root, []string{"claude"})
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	e.eng.childSIDs = []string{fresh, cleared}
	done, cancel := context.WithCancel(ctx)
	cancel() // one look, then return
	b.WatchSessions(done, plan, child)
	if e.eng.childAsks != 1 {
		t.Fatalf("asked the registry %d times, want once", e.eng.childAsks)
	}
	var sids []string
	for _, ev := range e.eng.ledgerEvs {
		if ev.Proc != child || ev.Type != ledger.TypeLaunch || !slices.Equal(ev.Roots, []string{"root-acme"}) {
			t.Fatalf("event %+v", ev)
		}
		sids = append(sids, ev.SID)
	}
	if !slices.Equal(sids, []string{fresh, cleared}) {
		t.Fatalf("recorded %v, want the fresh session once and the cleared one", sids)
	}
	// Back to the first session (/resume): recorded again as the child's
	// newest (D20), still once in the seal's scope.
	e.eng.childSIDs = []string{fresh}
	b.WatchSessions(done, plan, child)
	if n := len(e.eng.ledgerEvs); n != 3 || e.eng.ledgerEvs[2].SID != fresh {
		t.Fatalf("events after switching back %+v", e.eng.ledgerEvs)
	}
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutSealed, Files: 2, Bytes: 9}}}
	sum, err := b.SealAfterExit(ctx, plan, child)
	if err != nil || sum.Files != 2 {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if s := e.eng.sealScope[0]; len(s.SIDs) != 0 || !slices.Equal(s.RootIDs, []string{"root-acme"}) || !slices.Equal(s.Procs, []platform.ProcID{child}) {
		t.Fatalf("seal scope %+v, want every session the child owns in the folder, none named", s)
	}
	// A resume names its target; the sessions the child was seen running
	// join it.
	const target = "00000000-0000-4000-8000-0000000000e0"
	resumed := plan
	resumed.SessionID = ""
	resumed.Resume = harness.Resume{Kind: harness.ResumeSID, Value: target}
	resumed.SealScope = harness.Scope{SIDs: []string{target}, RootIDs: []string{"root-acme"}}
	if _, err := b.SealAfterExit(ctx, resumed, child); err != nil {
		t.Fatal(err)
	}
	if s := e.eng.sealScope[1]; !slices.Equal(s.SIDs, []string{target, fresh, cleared}) || !slices.Equal(s.Procs, []platform.ProcID{child}) {
		t.Fatalf("resume seal scope %+v, want its target and the sessions the child ran", s)
	}
	// ... and the ledger's newest session of the child, one only its hooks
	// recorded (a /clear the registry watch missed).
	const hooked = "00000000-0000-4000-8000-0000000000e4"
	e.eng.latest = []string{hooked}
	if _, err := b.SealAfterExit(ctx, resumed, child); err != nil {
		t.Fatal(err)
	}
	if s := e.eng.sealScope[2]; !slices.Equal(s.SIDs, []string{target, fresh, cleared, hooked}) {
		t.Fatalf("resume seal scope %+v, want the hook-recorded session too", s)
	}
	// Unmanaged launches are never watched.
	e.eng.childAsks = 0
	b.WatchSessions(done, harness.LaunchPlan{Harness: harness.ClaudeCode}, child)
	if e.eng.childAsks != 0 {
		t.Fatal("an unmanaged launch was watched")
	}
}

// D157: the wrapper measures the child's start once, right after the
// spawn (RecordLaunch), and compares every registry entry with that
// start, so a btime that moves later (a WSL 2 host sleep) or a floor from
// before the child (the earliest btime of the boot) changes nothing; a
// watch of another child measures that one.
func TestBackendWatchSessionsUsesTheStartAtLaunch(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}},
		SealScope: harness.Scope{RootIDs: []string{"root-acme"}}}
	want := platform.StartTime(child)
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel() // one look per call
	b.WatchSessions(done, plan, child)
	b.WatchSessions(done, plan, child)
	if len(e.eng.childStarted) != 2 {
		t.Fatalf("asked the registry %d times, want twice", len(e.eng.childStarted))
	}
	for _, got := range e.eng.childStarted {
		if got.IsZero() || !got.Equal(want) {
			t.Fatalf("compared with a start of %v, want the one measured at launch, %v", got, want)
		}
	}
	other := platform.ProcID{PID: 4321, StartUS: 7}
	b.WatchSessions(done, plan, other)
	if got := e.eng.childStarted[2]; !got.Equal(platform.StartTime(other)) {
		t.Fatalf("another child compared with %v", got)
	}
}

// D107: the exit lines name, and C5 resumes, the newest session of the
// child that the seal found a unit of — the ledger's newest (hooks or
// launch events), then those this run recorded from the last back: after
// a /clear the session the child ran last, not the one it started with;
// the one before when the last wrote nothing; none for a fresh launch
// whose sessions wrote nothing (C5 then suggests claude --continue), the
// target for a resume.
func TestBackendSummaryNamesTheSessionTheChildRanLast(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	const home = "aaaaaaaaaaaaaaaa"
	e.eng.homes = []harness.Home{{ID: "bbbbbbbbbbbbbbbb"}, {ID: home}}
	const fresh, cleared = "00000000-0000-4000-8000-0000000000e1", "00000000-0000-4000-8000-0000000000e2"
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}},
		SessionID: fresh, SealScope: harness.Scope{RootIDs: []string{"root-acme"}}}
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	e.eng.childSIDs = []string{cleared} // the user ran /clear
	done, cancel := context.WithCancel(ctx)
	cancel()
	b.WatchSessions(done, plan, child)
	unit := func(sid string, o sweep.Outcome) sweep.UnitResult {
		k, err := e.eng.UnitKey(capsule.KindClaudeSession, harness.ClaudeCode, home, "", sid)
		if err != nil {
			t.Fatal(err)
		}
		return sweep.UnitResult{Harness: "claude-code", Kind: capsule.KindClaudeSession, Unit: k, Outcome: o, Files: 1, Bytes: 5}
	}
	for _, tc := range []struct {
		name  string
		plan  harness.LaunchPlan
		units []sweep.UnitResult
		want  string
	}{
		{"both sessions sealed", plan, []sweep.UnitResult{unit(fresh, sweep.OutSealed), unit(cleared, sweep.OutSealed)}, cleared},
		{"the cleared session still held", plan, []sweep.UnitResult{unit(fresh, sweep.OutSealed), unit(cleared, sweep.OutLive)}, cleared},
		{"the cleared session wrote nothing", plan, []sweep.UnitResult{unit(fresh, sweep.OutUnchanged)}, fresh},
		{"nothing written", plan, nil, ""},
		{"another session's unit only", plan, []sweep.UnitResult{unit("00000000-0000-4000-8000-0000000000e9", sweep.OutSealed)}, ""},
		{"a resume that wrote nothing new", harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: plan.Roots,
			Resume: harness.Resume{Kind: harness.ResumeSID, Value: "00000000-0000-4000-8000-0000000000e0"}}, nil,
			"00000000-0000-4000-8000-0000000000e0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.eng.latest = []string{cleared}
			e.eng.sealRep = &sweep.Report{Units: tc.units}
			sum, err := b.SealAfterExit(ctx, tc.plan, child)
			if err != nil || sum.SID != tc.want {
				t.Fatalf("summary %+v err %v, want sid %q", sum, err, tc.want)
			}
		})
	}
	// A session only the hooks recorded (the registry was not read before
	// the exit) is the ledger's newest of the child.
	const hooked = "00000000-0000-4000-8000-0000000000e3"
	e.eng.latest = []string{hooked}
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{unit(fresh, sweep.OutSealed), unit(hooked, sweep.OutSealed)}}
	if sum, err := b.SealAfterExit(ctx, plan, child); err != nil || sum.SID != hooked {
		t.Fatalf("summary %+v err %v, want the hook-recorded session", sum, err)
	}
	// A seal that failed before it found any unit names the session the
	// child ran last (C6.failed says which one could not be sealed).
	e.eng.latest = nil
	e.eng.sealRep, e.eng.sealErr = nil, errors.New("scan failed")
	if sum, _ := b.SealAfterExit(ctx, plan, child); sum.SID != cleared || sum.Failed == "" {
		t.Fatalf("failed seal summary %+v", sum)
	}
}

// D107: units still held after exit are queued by unit key, so the worker
// finds them whatever sessions the child ran; a request names a session
// only when the scope names exactly one.
func TestBackendQueuesHeldUnitsByKey(t *testing.T) {
	const k1, k2 = "0123456789abcdef0123456789abcde1", "0123456789abcdef0123456789abcde2"
	child := platform.ProcID{PID: 1234, StartUS: 99}
	held := &sweep.Report{Units: []sweep.UnitResult{{Unit: k1, Outcome: sweep.OutLive}, {Unit: k2, Outcome: sweep.OutWarm},
		{Unit: "0123456789abcdef0123456789abcde3", Outcome: sweep.OutSealed, Files: 1}}}
	for _, tc := range []struct {
		name string
		sids []string
		want string
	}{
		{"one session", []string{"00000000-0000-4000-8000-0000000000e1"}, "00000000-0000-4000-8000-0000000000e1"},
		{"the child's sessions", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := testBackend(t)
			plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}},
				SealScope: harness.Scope{SIDs: tc.sids, RootIDs: []string{"root-acme"}}}
			e.eng.sealRep = held
			sum, err := b.SealAfterExit(context.Background(), plan, child)
			if err != nil || !sum.Deferred {
				t.Fatalf("summary %+v err %v", sum, err)
			}
			var keys []string
			for _, r := range e.eng.enqueued {
				if r.WaitFor != child || r.Reason != "wrapper-exit" || r.SID != tc.want {
					t.Fatalf("request %+v", r)
				}
				keys = append(keys, r.UnitKey)
			}
			if !slices.Equal(keys, []string{k1, k2}) {
				t.Fatalf("queued keys %v, want the two held units", keys)
			}
			if len(e.spawned) != 1 || strings.Join(e.spawned[0][1:], " ") != "seal --queue" {
				t.Fatalf("spawned %v", e.spawned)
			}
		})
	}
}

// UX-10, D110: a launch whose restores placed units under its lease ends
// in a folder that is locked by now: the lock's sweep left those units
// alone while the lease was held, so a keyless sweep of the folder runs
// after the exit. An unlocked folder keeps them (R4), and a launch that
// placed nothing needs no sweep.
func TestBackendSweepsALockedFolderItRestoredInto(t *testing.T) {
	ctx := context.Background()
	child := platform.ProcID{PID: 1234, StartUS: 99}
	for _, tc := range []struct {
		name     string
		place    bool
		unlocked bool
		want     bool
	}{
		{"locked with restored units", true, false, true},
		{"unlocked with restored units", true, true, false},
		{"locked, nothing restored", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := testBackend(t)
			if tc.unlocked {
				e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
			}
			plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}}}
			if _, err := b.AcquireLease(ctx, plan); err != nil {
				t.Fatal(err)
			}
			if tc.place {
				if err := b.beforePlace("0123456789abcdef0123456789abcdef"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := b.SealAfterExit(ctx, plan, child); err != nil {
				t.Fatal(err)
			}
			swept := false
			for _, argv := range e.spawned {
				if strings.Join(argv[1:], " ") == "sweep --root "+e.h.Root+" --quiet" {
					swept = true
				}
			}
			if swept != tc.want {
				t.Fatalf("spawned %v, want a sweep of the folder: %v", e.spawned, tc.want)
			}
		})
	}
}

// UX-11, D111: a seal the free-space floor refused never says "nothing to
// seal" and prints one line naming what it needs and the min_free it
// keeps, not the error chain; the exit code stays 1.
func TestSealNoSpacePrintsOneLine(t *testing.T) {
	e := newEnv(t)
	rep := &sweep.Report{Units: []sweep.UnitResult{{Harness: "claude-code", Kind: capsule.KindClaudeSession,
		Unit: "0123456789abcdef0123456789abcdef", Outcome: sweep.OutFailed, Files: 1, Bytes: 415,
		Detail: "no-space: sweep: not enough free space"}}}
	e.eng.sealRep, e.eng.sealErr = rep, rep.Err()
	code := e.run("seal", "--session", "00000000-0000-4000-8000-0000000000e1")
	if code != exitError {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(e.stdout(), "nothing to seal") {
		t.Fatalf("stdout %q says nothing to seal although a unit was refused", e.stdout())
	}
	want := "precinto: " + fmt.Sprintf(textSealNoSpace, 1, "415 B", "2GiB")
	if got := e.stderr(); got != want+"\n" {
		t.Fatalf("stderr %q, want only %q", got, want)
	}
	// A failure of another kind still prints its error (and no "nothing").
	e = newEnv(t)
	rep = &sweep.Report{Units: []sweep.UnitResult{{Kind: capsule.KindClaudeSession, Unit: "0123456789abcdef0123456789abcdef",
		Outcome: sweep.OutFailed, Detail: "failed: read: input/output error"}}}
	e.eng.sealRep, e.eng.sealErr = rep, rep.Err()
	if code := e.run("seal"); code != exitError || strings.Contains(e.stdout(), "nothing to seal") || !strings.Contains(e.stderr(), "seal: ") {
		t.Fatalf("exit %d stdout %q stderr %q", code, e.stdout(), e.stderr())
	}
}

// UX-17, D113: held units are listed by kind and reason, adopted sessions
// a sweep left alone are counted with the command that seals them, and a
// run from a terminal says why it waits.
func TestSealSummaryExplainsWhatStays(t *testing.T) {
	e := newEnv(t)
	e.eng.sweepRep = &sweep.Report{Units: []sweep.UnitResult{
		{Harness: "claude-code", Kind: capsule.KindClaudeHistory, Outcome: sweep.OutLive, Detail: "history_pending: process",
			Evidence: []live.Evidence{{Reason: live.ReasonProcess, Detail: "claude is running"}}},
		{Harness: "claude-code", Kind: capsule.KindClaudeSession, Outcome: sweep.OutLeased,
			Evidence: []live.Evidence{{Reason: live.ReasonLease}, {Reason: live.ReasonUnobserved, Weak: true}}},
		{Harness: "claude-code", Kind: capsule.KindClaudeSession, Outcome: sweep.OutSkipped, Files: 1, Detail: "adopted: seal --adopt"},
	}}
	if code := e.run("sweep"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	// The held units are listed under their line, indented and without
	// the "precinto: " prefix.
	want := strings.Join([]string{
		"precinto: " + fmt.Sprintf(textSealSkipped, 2),
		"  Claude prompt history (1): Claude is running",
		"  Claude session (1): a precinto run holds it",
		"precinto: " + fmt.Sprintf(textSealAdopted, 1),
	}, "\n") + "\n"
	if out := e.stdout(); out != want {
		t.Errorf("stdout\n%s\nwant\n%s", out, want)
	}
	// The quiet-window notice: on a terminal only.
	if o := e.eng.sweepOpts[0]; o.OnQuietWait == nil {
		t.Fatal("a sweep from a terminal has no quiet-wait notice")
	}
	e.out.Reset()
	e.app().quietWaitNotice()(2 * time.Minute)
	if got, want := e.stdout(), "precinto: "+fmt.Sprintf(textQuietWait, "2 min")+"\n"; got != want {
		t.Fatalf("notice %q, want %q", got, want)
	}
	e = newEnv(t)
	e.stdoutTTY = false
	if code := e.run("seal"); code != exitOK || e.eng.sealOpts[0].OnQuietWait != nil {
		t.Fatalf("exit %d; a seal without a terminal still announces its wait", code)
	}
	e = newEnv(t)
	if code := e.run("sweep", "--quiet"); code != exitOK || e.eng.sweepOpts[0].OnQuietWait != nil {
		t.Fatalf("exit %d; a quiet sweep announces its wait", code)
	}
}

// D111: a seal whose units were sealed but whose files could not all be
// removed says so (it printed nothing at all, and before D111 "nothing to
// seal"); the next sweep removes them, so the exit code stays 0.
func TestSealRemoveFailedSaysSo(t *testing.T) {
	e := newEnv(t)
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{{Harness: "claude-code", Kind: capsule.KindClaudeSession,
		Unit: "0123456789abcdef0123456789abcdef", Outcome: sweep.OutRemoveFailed, Files: 2, Bytes: 40,
		Detail: "1 file(s) could not be removed"}}}
	if code := e.run("seal"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if got, want := e.stdout(), "precinto: "+fmt.Sprintf(textRemoveFailed, 1)+"\n"; got != want {
		t.Fatalf("stdout %q, want %q", got, want)
	}
}

// UX-03, D109: a restore that met capsules of a Claude home config does
// not register says so with one catalog line naming the fix, and exits 1
// (a configuration gap), never 5 (verification failed); it does not also
// say "nothing to restore".
func TestRestoreFromAnUnregisteredHome(t *testing.T) {
	e := newEnv(t)
	rep := &sweep.Report{Units: []sweep.UnitResult{{Harness: "claude-code", Kind: capsule.KindClaudeSession,
		Unit: "0123456789abcdef0123456789abcdef", Outcome: sweep.OutFailed, Detail: "unregistered: harness: home is not registered"}}}
	e.eng.restoreRep, e.eng.restoreErr = rep, rep.Err()
	if !errors.Is(rep.Err(), harness.ErrUnregistered) {
		t.Fatalf("report error %v does not wrap ErrUnregistered", rep.Err())
	}
	code := e.run("restore") // what an unlock restores
	if code != exitError {
		t.Fatalf("exit %d, want 1 (never the tamper class 5)", code)
	}
	want := ui.Format(ui.MsgHomeUnregistered, ui.Vars{N: 1})
	if got := e.stderr(); got != want+"\n" {
		t.Fatalf("stderr %q, want only %q", got, want)
	}
	if got := e.stdout(); got != "" {
		t.Fatalf("stdout %q next to E.unregistered, want nothing", got)
	}
	if exitForRestore(harness.ErrUnregistered) != exitError || exitFor(harness.ErrUnregistered) != exitError {
		t.Fatal("ErrUnregistered must map to exit 1")
	}
}

// UX-17, D113: status's fix for a locked folder whose plaintext includes
// adopted sessions is seal --adopt, as doctor's (sweeps never seal them).
func TestStatusNamesSealAdoptForAdoptedPlaintext(t *testing.T) {
	e := newEnv(t)
	e.eng.plain = []sweep.Plaintext{{RootID: "root-acme", Files: 2, Bytes: 600, ByReason: map[string]int{"adopted": 1, "deferred": 1}}}
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	fixOf := func(s statusV1) string {
		for _, at := range s.Attention {
			if at.Code == ipc.AttnUnsealed {
				return at.Fix
			}
		}
		t.Fatalf("no unsealed attention item: %+v", s.Attention)
		return ""
	}
	if got, want := fixOf(s), "precinto seal --adopt --root ~/work/acme"; got != want {
		t.Fatalf("unsealed fix %q, want %q", got, want)
	}
	// A folder whose path needs quoting is named as one shell word.
	e = newEnv(t)
	spaced := filepath.Join(e.h.HomeDir, "My Work")
	if err := os.MkdirAll(spaced, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := e.h.Cfg
	cfg.Roots = append(append([]config.Root(nil), cfg.Roots...), config.Root{ID: "root-spaced", Path: spaced})
	if err := config.Save(e.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	e.eng.plain = []sweep.Plaintext{{RootID: "root-spaced", Files: 1, Bytes: 10, ByReason: map[string]int{"adopted": 1}}}
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	s = statusV1{}
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if got, want := fixOf(s), "precinto seal --adopt --root '"+spaced+"'"; got != want {
		t.Fatalf("unsealed fix %q, want %q", got, want)
	}
}

// D107: a job's session (attach, respawn) is written by its background
// worker, not by the child, so its seal scope sid gets no launch event of
// the child.
func TestBackendRecordLaunchSkipsAJobsSession(t *testing.T) {
	e, b := testBackend(t)
	ctx := context.Background()
	plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme"}},
		Resume:    harness.Resume{Kind: harness.ResumeJob, Value: "job-7"},
		SealScope: harness.Scope{SIDs: []string{"00000000-0000-4000-8000-0000000000e3"}}}
	if err := b.RecordLaunch(ctx, plan, platform.ProcID{PID: 1, StartUS: 2}); err != nil || len(e.eng.ledgerEvs) != 0 {
		t.Fatalf("attach wrote %+v (%v)", e.eng.ledgerEvs, err)
	}
}

// D114: a background seal registers a home (D109) by reading config.toml
// and writing it back under the config lock that every edit of the file
// takes, so an edit another process saves meanwhile (protect adding a
// folder) is kept; before, its unlocked read-modify-write could drop the
// new folder from config.toml and roots.list.
func TestRegisterHomesKeepsAConcurrentEdit(t *testing.T) {
	e := newEnv(t)
	a := e.app()
	l := e.h.Layout
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	held, err := fsx.TryLock(l.LockFile("config"), false)
	if err != nil {
		t.Fatal(err)
	}
	home := config.Home{Dir: filepath.Join(e.h.HomeDir, ".claude-work"), SeenAt: e.h.Clock.Now().UTC()}
	done := make(chan error, 1)
	go func() {
		_, err := a.registerHomes([]config.Home{home})
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("registerHomes wrote config.toml while another edit held its lock (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	// The other edit (protect in another process) saves a new folder.
	cfg, err := config.Load(l.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	added := config.Root{ID: "root-new", Path: filepath.Join(e.h.HomeDir, "new")}
	cfg.Roots = append(cfg.Roots, added)
	if err := config.Save(l.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	if err := held.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(l.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.RootByID(added.ID); !ok {
		t.Fatalf("the folder saved meanwhile was dropped: roots %+v", got.Roots)
	}
	registered := false
	for _, h := range got.Harness["claude-code"].Homes {
		registered = registered || h.Dir == home.Dir
	}
	if !registered {
		t.Fatalf("the home was not registered: %+v", got.Harness["claude-code"].Homes)
	}
	list, err := config.ReadRootsList(l.RootsList)
	if err != nil || !slices.Contains(list, added.Path) {
		t.Fatalf("roots.list %v (%v) lacks the folder saved meanwhile", list, err)
	}
}

// D147 (D6-1): a launch the wrapper refuses after its pre-exec restore
// placed units — the folder locked during or right after RestoreSync, or
// the child could not start — releases its lease without a child and never
// reaches SealAfterExit; the release itself spawns the keyless sweep of
// every folder of the plan that is locked by then, since the lock's sweep
// left the leased units alone. A launch whose child started leaves it to
// SealAfterExit, and one that placed nothing, or whose folder is unlocked,
// spawns nothing.
func TestRefusedLaunchSweepsTheLockedFolderItRestoredInto(t *testing.T) {
	ctx := context.Background()
	const unit = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name     string
		place    bool
		started  bool
		unlocked bool
		want     int
	}{
		{"refused after placing units in a locked folder", true, false, false, 1},
		{"refused, the folder still unlocked", true, false, true, 0},
		{"refused, nothing placed", false, false, false, 0},
		{"the child started (SealAfterExit sweeps)", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := testBackend(t)
			if tc.unlocked {
				e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
			}
			plan := harness.LaunchPlan{Harness: harness.ClaudeCode, Roots: []config.Root{{ID: "root-acme", Path: e.h.Root}},
				Sync: []harness.Selector{{Kind: capsule.KindClaudeSession, Keys: []string{unit}}}}
			lease, err := b.AcquireLease(ctx, plan)
			if err != nil || lease == nil {
				t.Fatalf("lease %v %v", lease, err)
			}
			abort := make(chan struct{})
			e.eng.restoreFn = func(keys sweep.KeySource, r sweep.RestoreRequest) {
				if tc.place {
					if err := r.BeforePlace(unit); err != nil {
						t.Error(err)
					}
				}
				close(abort) // the folder locks meanwhile (REST-8)
			}
			if _, err := b.RestoreSync(ctx, plan, abort); err != nil {
				t.Fatal(err)
			}
			if tc.started {
				if err := lease.SetChild(platform.ProcID{PID: 1234, StartUS: 99}); err != nil {
					t.Fatal(err)
				}
			}
			if err := lease.Release(); err != nil {
				t.Fatal(err)
			}
			_ = lease.Release() // a second release sweeps nothing more
			n := 0
			for _, argv := range e.spawned {
				if strings.Join(argv[1:], " ") == "sweep --root "+e.h.Root+" --quiet" {
					n++
				}
			}
			if n != tc.want {
				t.Fatalf("spawned %v, want %d sweep(s) of the folder", e.spawned, tc.want)
			}
		})
	}
}
