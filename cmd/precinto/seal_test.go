package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
)

func TestSealOptions(t *testing.T) {
	e := newEnv(t)
	e.eng.sealRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutSealed, Files: 4, Bytes: 2000}, {Outcome: sweep.OutLive}}}
	code := e.run("seal", "--harness", "claude-code", "--session", "sid1", "--root", e.h.Root, "--wait-pid", "123:456", "--adopt", "--dry-run")
	if code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if e.hardened != 1 {
		t.Fatal("seal did not harden (SPEC §4.6)")
	}
	o := e.eng.sealOpts[0]
	if !o.Adopt || !o.DryRun || o.WaitFor == nil || *o.WaitFor != (platform.ProcID{PID: 123, StartUS: 456}) {
		t.Fatalf("options %+v", o)
	}
	if s := e.eng.sealScope[0]; len(s.SIDs) != 1 || s.SIDs[0] != "sid1" || s.RootIDs[0] != "root-acme" {
		t.Fatalf("scope %+v", s)
	}
	if hs := e.eng.sealHarness[0]; len(hs) != 1 || hs[0] != harness.ClaudeCode {
		t.Fatalf("harnesses %v", hs)
	}
	if !strings.Contains(e.stdout(), "sealed 1 unit(s) (4 files, 2 kB).") || !strings.Contains(e.stdout(), "1 unit(s) are still in use") {
		t.Fatalf("stdout %q", e.stdout())
	}
	if len(e.dials) != 0 {
		t.Fatal("seal dialled the daemon itself (it never needs a key)")
	}
}

func TestSealExitCodes(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{sweep.ErrLive, exitLive},
		{sweep.ErrTripwire, exitVerify},
		{capsule.ErrHeader, exitVerify},
		{errors.Join(errors.New("io"), sweep.ErrLive), exitLive},
	}
	for _, c := range cases {
		e := newEnv(t)
		e.eng.sealErr = c.err
		if code := e.run("seal"); code != c.want {
			t.Errorf("%v: exit %d, want %d", c.err, code, c.want)
		}
	}
	e := newEnv(t)
	if code := e.run("seal", "--wait-pid", "nope"); code != exitUsage {
		t.Errorf("bad --wait-pid: exit %d", code)
	}
}

func TestSealQueueAndDormant(t *testing.T) {
	e := newEnv(t)
	if code := e.run("seal", "--queue"); code != exitOK || !e.eng.called("DrainQueue") {
		t.Fatalf("exit %d calls %v", code, e.eng.calls)
	}
	if o := e.eng.drainOpts[0]; o.Reason != "session-end" || !o.Quiet {
		t.Fatalf("drain options %+v", o)
	}
	e = newEnv(t)
	if code := e.run("seal", "--dormant", "gemini"); code != exitUsage {
		t.Fatalf("dormant without --experimental: exit %d", code)
	}
	e = newEnv(t)
	if code := e.run("seal", "--dormant", "gemini", "--experimental"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if o := e.eng.sealOpts[0]; o.Dormant != "gemini" || !e.engExp[0] {
		t.Fatalf("options %+v experimental %v", o, e.engExp)
	}
}

// sweep: a busy sweep lock is not an error (another sweep rescans,
// SPEC §10.2); --quiet prints nothing.
func TestSweep(t *testing.T) {
	e := newEnv(t)
	e.eng.sweepErr = sweep.ErrBusy
	if code := e.run("sweep", "--quiet"); code != exitOK {
		t.Fatalf("busy: exit %d", code)
	}
	if e.stdout() != "" || e.stderr() != "" {
		t.Fatalf("quiet sweep printed %q %q", e.stdout(), e.stderr())
	}
	e = newEnv(t)
	if code := e.run("sweep", "--lock", "--root", e.h.Root, "--wait", "--dry-run"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	o := e.eng.sweepOpts[0]
	if !o.Lock || !o.Wait || !o.DryRun || o.Reason != "lock" || o.Scope.RootIDs[0] != "root-acme" {
		t.Fatalf("options %+v", o)
	}
	e = newEnv(t)
	e.eng.sweepErr = sweep.ErrTripwire
	if code := e.run("sweep"); code != exitVerify {
		t.Fatalf("tripwire: exit %d", code)
	}
}

// restore with no selection restores what an unlock restores (UX12):
// recent sessions within the retention age (D14), the project unit, notes
// and history.
func TestRestoreDefault(t *testing.T) {
	e := newEnv(t)
	e.eng.restoreRep = &sweep.Report{Units: []sweep.UnitResult{{Outcome: sweep.OutRestored, Files: 2, Bytes: 10}, {Outcome: sweep.OutConflict}}}
	if code := e.run("restore"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	r := e.eng.restores[0]
	if r.Purpose != ipc.PurposeRestore || r.Abort == nil || r.Budget != 0 {
		t.Fatalf("request %+v", r)
	}
	s := r.Select[0]
	if s.Kind != capsule.KindClaudeSession || s.RootID != "root-acme" || s.Recent != 5 || s.MaxAge != 28*24*3600*1e9 {
		t.Fatalf("selector %+v", s)
	}
	if r.Select[1].Kind != capsule.KindClaudeProject {
		t.Fatalf("selectors %+v", r.Select)
	}
	if !e.eng.called("RestoreMarkdown") || !e.eng.called("MergeHistory") {
		t.Fatalf("calls %v", e.eng.calls)
	}
	if !strings.Contains(e.stdout(), "restored 1 unit(s) (2 files, 10 B).") || !strings.Contains(e.stdout(), "precinto ls --conflicts") {
		t.Fatalf("stdout %q", e.stdout())
	}
	if len(e.eng.restores) != 1 {
		t.Fatalf("restores %d", len(e.eng.restores))
	}
}

// restore --session selects the sid's unit key in every registered Claude
// home; it is explicit, so no budget applies.
func TestRestoreSession(t *testing.T) {
	e := newEnv(t)
	e.eng.homes = []harness.Home{{ID: "aaaaaaaaaaaaaaaa"}, {ID: "bbbbbbbbbbbbbbbb"}}
	if code := e.run("restore", "--session", "00000000-0000-4000-8000-000000000001"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	r := e.eng.restores[0]
	if r.Budget != math.MaxInt64 || len(r.Select) != 1 || len(r.Select[0].Keys) != 2 || r.Select[0].RootID != "" {
		t.Fatalf("request %+v", r)
	}
	if e.eng.called("RestoreMarkdown") {
		t.Fatal("--session restored notes too")
	}
}

// restore --all uses purpose restore-all (fresh presence from agents and
// TTY-less peers, decided by the daemon, D28, D59).
func TestRestoreAllPurpose(t *testing.T) {
	e := newEnv(t)
	if code := e.run("restore", "--all"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if p := e.eng.restores[0].Purpose; p != ipc.PurposeRestoreAll {
		t.Fatalf("purpose %q", p)
	}
	kinds := map[capsule.Kind]bool{}
	for _, s := range e.eng.restores[0].Select {
		kinds[s.Kind] = true
	}
	for _, k := range []capsule.Kind{capsule.KindClaudeSession, capsule.KindClaudeProject, capsule.KindClaudePlan, capsule.KindCodexHome} {
		if !kinds[k] {
			t.Errorf("--all misses %s", k)
		}
	}
}

func TestRestoreRefusals(t *testing.T) {
	e := newEnv(t)
	e.cwd = e.h.HomeDir
	if code := e.run("restore"); code != exitUsage {
		t.Fatalf("outside a folder: exit %d", code)
	}
	e = newEnv(t)
	e.eng.restoreErr = capsule.ErrVerify
	if code := e.run("restore", "--recent", "1"); code != exitVerify {
		t.Fatalf("verify: exit %d", code)
	}
	e = newEnv(t)
	e.eng.restoreErr = errors.Join(sweep.ErrKeyDenied)
	if code := e.run("restore", "--recent", "1"); code != exitLocked {
		t.Fatalf("locked: exit %d", code)
	}
	// --global alone works outside a folder.
	e = newEnv(t)
	e.cwd = e.h.HomeDir
	if code := e.run("restore", "--global"); code != exitOK || e.eng.restores[0].Select[0].Kind != capsule.KindGlobalStore {
		t.Fatalf("global: exit %d %+v", code, e.eng.restores)
	}
}

// DC-24: restore --global restores Claude's global stores and the units of
// experimental harnesses; --harness H narrows it to one harness, and needs
// --global.
func TestRestoreGlobalHarness(t *testing.T) {
	units := []sweep.UnitInfo{
		{Harness: "gemini", Kind: capsule.KindGeneric, Unit: "1111111111111111111111111111111a"},
		{Harness: "kimi", Kind: capsule.KindGeneric, Unit: "2222222222222222222222222222222b"},
		{Harness: "claude-code", Kind: capsule.KindClaudeSession, Unit: "3333333333333333333333333333333c", RootIDs: []string{"root-acme"}},
	}
	kinds := func(e *env) map[capsule.Kind][]string {
		m := map[capsule.Kind][]string{}
		for _, s := range e.eng.restores[0].Select {
			m[s.Kind] = append(m[s.Kind], s.Keys...)
		}
		return m
	}
	e := newEnv(t)
	e.cwd = e.h.HomeDir
	e.eng.units = units
	if code := e.run("restore", "--global"); code != exitOK {
		t.Fatalf("global: exit %d (%s)", code, e.stderr())
	}
	k := kinds(e)
	if _, ok := k[capsule.KindGlobalStore]; !ok || strings.Join(k[capsule.KindGeneric], ",") != units[0].Unit+","+units[1].Unit {
		t.Fatalf("global selects %v", k)
	}
	e = newEnv(t)
	e.cwd = e.h.HomeDir
	e.eng.units = units
	if code := e.run("restore", "--global", "--harness", "kimi"); code != exitOK {
		t.Fatalf("--harness kimi: exit %d (%s)", code, e.stderr())
	}
	k = kinds(e)
	if _, ok := k[capsule.KindGlobalStore]; ok || strings.Join(k[capsule.KindGeneric], ",") != units[1].Unit {
		t.Fatalf("--harness kimi selects %v", k)
	}
	e = newEnv(t)
	e.cwd = e.h.HomeDir
	e.eng.units = units
	if code := e.run("restore", "--global", "--harness", "claude-code"); code != exitOK {
		t.Fatalf("--harness claude-code: exit %d (%s)", code, e.stderr())
	}
	if sel := e.eng.restores[0].Select; len(sel) != 1 || sel[0].Kind != capsule.KindGlobalStore {
		t.Fatalf("--harness claude-code selects %+v, want only the global stores", sel)
	}
	e = newEnv(t)
	if code := e.run("restore", "--harness", "kimi"); code != exitUsage || len(e.eng.restores) != 0 {
		t.Fatalf("--harness without --global: exit %d", code)
	}
}

// The post-unlock worker is quiet and never consults the agent context.
func TestRestoreBackgroundQuiet(t *testing.T) {
	e := newEnv(t)
	if code := e.run("restore", "--root", e.h.Root, "--recent", "5", "--md", "--history", "--background"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if e.stdout() != "" {
		t.Fatalf("background restore printed %q", e.stdout())
	}
}

func TestLsJSONHasNoTitles(t *testing.T) {
	e := newEnv(t)
	e.eng.units = []sweep.UnitInfo{{Harness: "claude-code", Kind: capsule.KindClaudeSession, Unit: "0123456789abcdef0123456789abcdef",
		RootIDs: []string{"root-acme"}, Gens: []sweep.Generation{{Gen: 1}, {Gen: 3}}, Bytes: 10, Title: "secret title"}}
	if code := e.run("ls", "--json"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(e.stdout(), "secret title") {
		t.Fatal("ls --json leaked a title (content)")
	}
	var got []lsUnit
	if err := json.Unmarshal(e.out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Generations != 2 || got[0].Newest != 3 || got[0].Folders[0] != "~/work/acme" {
		t.Fatalf("%+v", got)
	}
	if e.eng.listOpts[0].Keys != nil {
		t.Fatal("ls --json asked for keys (titles)")
	}
}

// ls on a terminal asks for titles (purpose list) and falls back to none
// when the daemon refuses.
func TestLsTitlesOnTerminal(t *testing.T) {
	e := newEnv(t)
	e.eng.listErr = sweep.ErrKeyDenied
	calls := 0
	e.eng.units = nil
	a := e.app()
	inner := e.eng
	a.sys.engine = func(ctxx context.Context, _ *app, _ bool) (engine, error) {
		return &listFallback{fakeEngine: inner, calls: &calls}, nil
	}
	if code := a.run([]string{"ls"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if calls != 2 {
		t.Fatalf("List called %d times, want a retry without titles", calls)
	}
}

type listFallback struct {
	*fakeEngine
	calls *int
}

func (l *listFallback) List(ctx context.Context, o sweep.ListOptions) ([]sweep.UnitInfo, error) {
	*l.calls++
	if o.Keys != nil {
		return nil, sweep.ErrKeyDenied
	}
	return nil, nil
}

func TestOpenValidatesMarkers(t *testing.T) {
	e := newEnv(t)
	marker := filepath.Join(e.h.Root, "notes.md.precinto")
	e.eng.markers[marker] = "0123456789abcdef0123456789abcdef"
	if code := e.run("open", "notes.md.precinto"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.eng.opened) != 1 || e.eng.opened[0][0] != marker {
		t.Fatalf("opened %v", e.eng.opened)
	}
	e = newEnv(t)
	if code := e.run("open", "not-a-marker.md"); code != exitUsage {
		t.Fatalf("non-marker: exit %d (ErrNotMarker is exit 2)", code)
	}
	if e.eng.called("OpenNotes") {
		t.Fatal("opened a non-marker")
	}
}

// S17: cat writes plaintext only to a terminal, sanitized unless --raw,
// or to a new 0600 file with --to.
func TestCat(t *testing.T) {
	e := newEnv(t)
	marker := filepath.Join(e.h.Root, "n.md.precinto")
	e.eng.markers[marker] = "0123456789abcdef0123456789abcdef"
	e.eng.catBody = "héllo\x1b[2J wörld\x9b\n"
	if code := e.run("cat", marker); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if got := e.stdout(); got != "héllo[2J wörld\n" {
		t.Fatalf("sanitized %q", got)
	}

	e.out.Reset()
	if code := e.run("cat", marker, "--raw"); code != exitOK || e.stdout() != e.eng.catBody {
		t.Fatalf("raw: exit %d %q", code, e.stdout())
	}

	e.out.Reset()
	e.stdoutTTY = false
	if code := e.run("cat", marker); code != exitUsage {
		t.Fatalf("non-tty: exit %d", code)
	}
	if e.stdout() != "" {
		t.Fatal("plaintext written to a non-terminal")
	}

	out := filepath.Join(e.h.Dir, "out.md")
	if code := e.run("cat", marker, "--to", out); code != exitOK {
		t.Fatalf("--to: exit %d (%s)", code, e.stderr())
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != e.eng.catBody {
		t.Fatalf("file %q err %v", b, err)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if code := e.run("cat", marker, "--to", out); code != exitError {
		t.Fatalf("existing --to: exit %d (never overwrite)", code)
	}
}

func TestSanitizingWriterSplitRunes(t *testing.T) {
	var b strings.Builder
	w := &sanitizingWriter{w: &b}
	in := []byte("aé\xc2\x9bz") // é, then U+009B (a C1 control) split below
	for i := range in {
		w.Write(in[i : i+1])
	}
	w.flush()
	if b.String() != "aéz" {
		t.Fatalf("%q", b.String())
	}
}

func TestResolve(t *testing.T) {
	e := newEnv(t)
	if code := e.run("resolve", "notes.md", "--keep", "capsule"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if want := filepath.Join(e.h.Root, "notes.md") + "=capsule"; e.eng.resolved[0] != want {
		t.Fatalf("resolved %v", e.eng.resolved)
	}
	e = newEnv(t)
	e.tty.lines = []string{"plaintext"}
	if code := e.run("merge", "notes.md"); code != exitOK || !strings.HasSuffix(e.eng.resolved[0], "=plaintext") {
		t.Fatalf("exit %d %v", code, e.eng.resolved)
	}
	e = newEnv(t)
	e.tty = nil
	if code := e.run("resolve", "notes.md"); code != exitUsage {
		t.Fatalf("no tty, no --keep: exit %d", code)
	}
}

// forget resolves a marker or a note path to its unit key (md unit keys
// are derived from the folder and the relpath, SPEC §6.2).
func TestForgetUnitResolution(t *testing.T) {
	e := newEnv(t)
	a := e.app()
	cfg, _ := a.config()
	marker := filepath.Join(e.h.Root, "docs", "n.md.precinto")
	e.eng.markers[marker] = "0123456789abcdef0123456789abcdef"
	if unit, _, err := a.unitOf(cfg, e.eng, marker); err != nil || unit != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("marker: %q %v", unit, err)
	}
	mkdir(t, filepath.Join(e.h.Root, "docs"))
	unit, _, err := a.unitOf(cfg, e.eng, filepath.Join(e.h.Root, "docs", "n.md"))
	want, _ := e.eng.UnitKey(capsule.KindMarkdown, "", "", "root-acme", "docs/n.md")
	if err != nil || unit != want {
		t.Fatalf("note: %q %v (want %q)", unit, err, want)
	}
	if _, _, err := a.unitOf(cfg, e.eng, filepath.Join(e.h.HomeDir, "x.md")); err == nil {
		t.Fatal("a note outside every folder resolved")
	}
}

func TestCodexSubcommands(t *testing.T) {
	e := newEnv(t)
	if code := e.run("codex", "reconcile", "--root", e.h.Root, "--prefer", "capsule"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if e.eng.reconciled[0] != "root-acme=capsule" {
		t.Fatalf("%v", e.eng.reconciled)
	}
	if code := e.run("codex", "reconcile", "--root", e.h.Root); code != exitUsage {
		t.Fatalf("missing --prefer: exit %d", code)
	}
	if code := e.run("codex", "sync-config", "--root", e.h.Root); code != exitOK || e.eng.prepared[0] != "root-acme:true" {
		t.Fatalf("exit %d %v", code, e.eng.prepared)
	}
	if code := e.run("codex", "sync-config"); code != exitUsage {
		t.Fatalf("no --root: exit %d", code)
	}
}

// --recent 0 restores no session (a zero Selector.Recent would mean every
// match; a zero counter is "none", D62).
func TestRestoreRecentZero(t *testing.T) {
	e := newEnv(t)
	if code := e.run("restore", "--recent", "0"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, s := range e.eng.restores[0].Select {
		if s.Kind == capsule.KindClaudeSession {
			t.Fatalf("a session selector for --recent 0: %+v", s)
		}
	}
}

// REST-8 at the CLI: a lock while the restore runs (after the folder's
// initial unlocked state, D71) stops it, and restore exits 3 with the
// stopped-restore text instead of reporting success; a folder already
// locked when the restore starts is not a lock during it.
func TestRestoreStoppedByALock(t *testing.T) {
	e := newEnv(t)
	e.eng.homes = []harness.Home{{ID: "aaaaaaaaaaaaaaaa"}}
	e.daemon.events = make(chan ipc.Event, 4)
	e.eng.restoreFn = func(_ sweep.KeySource, r sweep.RestoreRequest) {
		e.daemon.events <- ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-acme"}}
		e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}}
		<-r.Abort // the engine stops at the abort (rolling back what is not staged)
	}
	if code := e.run("restore", "--session", "sid1"); code != exitLocked {
		t.Fatalf("restore interrupted by a lock: exit %d, want %d (%s)", code, exitLocked, e.stderr())
	}
	if !strings.Contains(e.stderr(), textRestoreStopped) {
		t.Errorf("no stopped-restore text: %q", e.stderr())
	}

	e = newEnv(t)
	e.eng.homes = []harness.Home{{ID: "aaaaaaaaaaaaaaaa"}}
	e.daemon.events = make(chan ipc.Event, 4)
	e.eng.restoreFn = func(_ sweep.KeySource, r sweep.RestoreRequest) {
		e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}} // the initial state
		select {
		case <-r.Abort:
			t.Error("the folder's initial locked state aborted the restore (D71)")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if code := e.run("restore", "--session", "sid1"); code != exitOK {
		t.Fatalf("restore with nothing interrupted: exit %d (%s)", code, e.stderr())
	}
}
