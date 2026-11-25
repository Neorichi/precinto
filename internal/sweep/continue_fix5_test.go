package sweep

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/claude/claudetest"
	"github.com/Neorichi/precinto/internal/testkit"
)

// startLine is a ledger start line of session sid with the SessionStart
// source and the process's entrypoint.
func startLine(sid, source, entrypoint string) string {
	return `{"v":1,"t":"2026-11-21T08:00:00Z","type":"start","harness":"claude-code","sid":"` + sid +
		`","source":"` + source + `","entrypoint":"` + entrypoint + `"}` + "\n"
}

// sealWithLedger seals the session as it is on disk now, with raw as the
// ledger lines that go into its manifest (S13), and returns the unit.
func (te *testEnv) sealWithLedger(sid, raw string) harness.Unit {
	te.t.Helper()
	u := te.scanSession(sid)
	u.ProjectDir = te.h.Root
	te.ledger.mu.Lock()
	te.ledger.raw["claude-code/"+sid] = []byte(raw)
	te.ledger.mu.Unlock()
	rep, err := te.run().sealCommand(tctx(te.t), []harness.Unit{u}, Options{})
	mustNoErr(te.t, err)
	if res := outcome(te.t, rep, u.Key); res.Outcome != OutSealed {
		te.t.Fatalf("seal %+v", res)
	}
	return u
}

// sealedWithEntrypoint seals a session of the folder whose transcript is age
// old and whose ledger (moved into the manifest) records its creation
// (source startup) by entrypoint; "" writes no ledger.
func (te *testEnv) sealedWithEntrypoint(sid, entrypoint string, age time.Duration) harness.Unit {
	te.t.Helper()
	te.writeSession(sid, "", func(s *claudetest.Session) { s.ModTime = testkit.Epoch.Add(-age) })
	raw := ""
	if entrypoint != "" {
		raw = startLine(sid, "startup", entrypoint) +
			`{"v":1,"t":"2026-11-21T08:01:00Z","type":"cwd","harness":"claude-code","sid":"` + sid + `","cwd":"/elsewhere"}` + "\n"
	}
	return te.sealWithLedger(sid, raw)
}

// sdkEntrypoints are the entrypoints Claude Code 2.1.329's interactive
// --continue skips (sessions of claude -p and the Agent SDKs).
var sdkEntrypoints = []string{"sdk-cli", "sdk-ts", "sdk-py"}

func restored(rep *Report, key string) bool {
	for _, u := range rep.Units {
		if u.Unit == key && u.Outcome == OutRestored {
			return true
		}
	}
	return false
}

// D102 (M5): the -c selector restores the newest session Claude's
// interactive --continue can pick: a newer session whose ledger records
// claude -p (sdk-cli) is skipped, so the older interactive one is there
// before Claude starts; a unit that records no entrypoint is kept.
func TestContinueSelectorSkipsSDKSessions(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	older := te.sealedWithEntrypoint(sid1, "cli", 3*time.Hour)
	newer := te.sealedWithEntrypoint(sid2, "sdk-cli", time.Hour)
	cont := func(te *testEnv) harness.Selector {
		return harness.Selector{Kind: capsule.KindClaudeSession, RootID: rootID, ProjectDir: te.h.Root, Newest: true, MtimeNow: true,
			SkipEntrypoints: sdkEntrypoints}
	}
	rep := te.restoreUnits(RestoreRequest{Select: []harness.Selector{cont(te)}})
	if !restored(rep, older.Key) || restored(rep, newer.Key) {
		t.Fatalf("-c restored %+v: want the older interactive session, not the newer claude -p one", rep.Units)
	}

	te = newTestEnv(t)
	cli := te.sealedWithEntrypoint(sid1, "cli", 3*time.Hour)
	sdk := te.sealedWithEntrypoint(sid2, "sdk-ts", 2*time.Hour)
	unknown := te.sealedWithEntrypoint("00000000-0000-4000-8000-0000000000a3", "", time.Hour)
	sel := cont(te)
	sel.Newest, sel.Recent = false, 5
	rep = te.restoreUnits(RestoreRequest{Select: []harness.Selector{sel}})
	if !restored(rep, cli.Key) || !restored(rep, unknown.Key) || restored(rep, sdk.Key) {
		t.Fatalf("recent with SDK sessions skipped: %+v", rep.Units)
	}
	// Without SkipEntrypoints (claude -p -c) every session counts.
	te = newTestEnv(t)
	te.sealedWithEntrypoint(sid1, "cli", 3*time.Hour)
	newest := te.sealedWithEntrypoint(sid2, "sdk-cli", time.Hour)
	sel = cont(te)
	sel.SkipEntrypoints = nil
	if rep := te.restoreUnits(RestoreRequest{Select: []harness.Selector{sel}}); !restored(rep, newest.Key) {
		t.Fatalf("print-mode continue: %+v", rep.Units)
	}
}

// D102: the selectors of an interactive `claude -c` (plan.go) in the request
// the wrapper's RestoreSync sends (MtimeNow set from them, StopOnErr).
func continueSelectors(te *testEnv) []harness.Selector {
	return []harness.Selector{
		{Kind: capsule.KindClaudeSession, RootID: rootID, ProjectDir: te.h.Root, Newest: true, MtimeNow: true, SkipEntrypoints: sdkEntrypoints},
		{Kind: capsule.KindClaudeProject, RootID: rootID},
		{Kind: capsule.KindClaudeSession, RootID: rootID, ProjectDir: te.h.Root, Recent: 5, MaxAge: 28 * 24 * time.Hour, SkipEntrypoints: sdkEntrypoints},
	}
}

// D102, D14 (M5): Claude's --continue picks the newest transcript by mtime.
// After days away, the newest pickable session is clamped to now − 1 day
// (so Claude's cleanup keeps it), which keeps it the newest; the other
// recent sessions restored with it keep their own mtimes — they are not
// clamped to that same time, which would leave Claude to continue the
// last one placed. A request MtimeNow covers explicit units only.
func TestContinueRestoreKeepsClaudesOrder(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	day := 24 * time.Hour
	newest := te.sealedWithEntrypoint(sid1, "cli", 2*day)
	mid := te.sealedWithEntrypoint(sid2, "cli", 3*day)
	oldest := te.sealedWithEntrypoint("00000000-0000-4000-8000-0000000000a3", "cli", 4*day)
	rep := te.restoreUnits(RestoreRequest{Select: continueSelectors(te), MtimeNow: true, StopOnErr: true})
	for _, u := range []harness.Unit{newest, mid, oldest} {
		if !restored(rep, u.Key) {
			t.Fatalf("not restored before exec: %+v", rep.Units)
		}
	}
	mtime := func(u harness.Unit) time.Time {
		t.Helper()
		st, err := fsx.Lstat(transcriptOf(u))
		mustNoErr(t, err)
		return time.Unix(0, st.MtimeNS)
	}
	if floor := te.h.Clock.Now().Add(-day); mtime(newest).Before(floor) {
		t.Errorf("newest pickable session not clamped: %v, floor %v", mtime(newest), floor)
	}
	for _, u := range []harness.Unit{mid, oldest} {
		if want := testkit.Epoch.Add(-time.Duration(map[string]int{mid.Key: 3, oldest.Key: 4}[u.Key]) * day); !mtime(u).Equal(want) {
			t.Errorf("%s: mtime %v, want its own %v", u.UnitID, mtime(u), want)
		}
	}
	if !mtime(newest).After(mtime(mid)) || !mtime(mid).After(mtime(oldest)) {
		t.Errorf("Claude's order lost: newest %v, mid %v, oldest %v", mtime(newest), mtime(mid), mtime(oldest))
	}
}

// continueInPlace restores a sealed session, appends a turn to its
// transcript (a later process continued it under the same id) and seals
// it again with raw as the ledger lines of that process: the second
// generation, a successor of the first.
func (te *testEnv) continueInPlace(u harness.Unit, raw string) harness.Unit {
	te.t.Helper()
	if rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}}); !restored(rep, u.Key) {
		te.t.Fatalf("restore %+v", rep.Units)
	}
	p := transcriptOf(u)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	mustNoErr(te.t, err)
	_, err = f.WriteString(`{"type":"user","sessionId":"` + u.UnitID + `","message":{"role":"user","content":"go on"}}` + "\n")
	mustNoErr(te.t, errors.Join(err, f.Close()))
	mt := testkit.Epoch.Add(-time.Hour)
	mustNoErr(te.t, os.Chtimes(p, mt, mt))
	next := te.sealWithLedger(u.UnitID, raw)
	gens, err := Generations(te.e, u.Key)
	if err != nil || len(gens) != 2 || gens[1].Lineage != capsule.LineageSuccessor {
		te.t.Fatalf("generations %+v %v", gens, err)
	}
	return next
}

// D102 (M5): a session is classified by the entrypoint of its creation.
// An interactive session later continued in place by `claude -p -c` gets a
// second generation whose ledger holds only that resume (sdk-cli): it is
// still the session Claude's interactive --continue picks, so -c restores
// it. A session created by claude -p and resumed interactively has no
// creation line in its newest generation either: it is kept (precinto
// cannot tell), and the session Claude picks instead is restored too.
func TestContinueClassifiesASessionByItsCreation(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	day := 24 * time.Hour
	older := te.sealedWithEntrypoint(sid2, "cli", 3*day)
	cont := te.continueInPlace(te.sealedWithEntrypoint(sid1, "cli", 2*day), startLine(sid1, "resume", "sdk-cli"))
	rep := te.restoreUnits(RestoreRequest{Select: continueSelectors(te), MtimeNow: true, StopOnErr: true})
	if !restored(rep, cont.Key) || !restored(rep, older.Key) {
		t.Fatalf("-c after a claude -p -c continuation: %+v", rep.Units)
	}

	te = newTestEnv(t)
	cli := te.sealedWithEntrypoint(sid2, "cli", 3*day)
	resumed := te.continueInPlace(te.sealedWithEntrypoint(sid1, "sdk-cli", 2*day), startLine(sid1, "resume", "cli"))
	rep = te.restoreUnits(RestoreRequest{Select: continueSelectors(te), MtimeNow: true, StopOnErr: true})
	if !restored(rep, resumed.Key) || !restored(rep, cli.Key) {
		t.Fatalf("-c after an SDK session resumed interactively: %+v", rep.Units)
	}
}

// ledgerEntrypoint reads the entrypoint of the session's own creation line
// (a start with source startup or clear), skipping lines that do not
// decode, belong to another session, or record a resume, compaction, fork
// or first contact.
func TestLedgerEntrypoint(t *testing.T) {
	line := func(sid, source, ep string) string {
		return `{"type":"start","sid":"` + sid + `","source":"` + source + `","entrypoint":"` + ep + `"}` + "\n"
	}
	for raw, want := range map[string]string{
		"": "",
		`{"type":"launch","sid":"` + sid1 + `"}` + "\n" + line(sid1, "startup", "sdk-cli") + line(sid1, "resume", "cli"): "sdk-cli",
		"not json\n" + line(sid1, "startup", "cli"):                                            "cli",
		line(sid1, "clear", "cli"):                                                             "cli",
		`{"type":"start","sid":"` + sid1 + `","source":"startup","entrypoint":7}` + "\n":       "",
		line(sid2, "startup", "sdk-cli") + line(sid1, "startup", "cli"):                        "cli",
		line(sid1, "resume", "sdk-cli"):                                                        "",
		line(sid1, "compact", "sdk-cli") + line(sid1, "fork", "sdk-cli"):                       "",
		line(sid1, "", "sdk-cli"):                                                              "",
		`{"type":"cwd","sid":"` + sid1 + `","source":"startup","entrypoint":"sdk-cli"}` + "\n": "",
	} {
		if got := ledgerEntrypoint([]byte(raw), sid1); got != want {
			t.Errorf("ledgerEntrypoint(%q) = %q, want %q", raw, got, want)
		}
	}
}
