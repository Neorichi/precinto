package claude_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/testkit"
)

var salt = []byte("precinto-test-salt-0123456789abc")

// fx is a fake HOME with a registered Claude home and one protected root.
type fx struct {
	t      *testing.T
	h      *testkit.Home
	l      *claudetest.Layout
	e      harness.Env
	a      harness.Adapter
	homeID string
	marker string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	h := testkit.NewHome(t)
	// File mtimes are real time: start the clock there (no "future" files).
	h.Clock = fakeplatform.NewClock(time.Now())
	f := &fx{t: t, h: h, a: claude.New(), marker: testkit.Marker(t)}
	f.l = &claudetest.Layout{ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp, CacheDir: h.ClaudeCache}
	f.e = harness.Env{
		Cfg: h.Cfg, Layout: h.Layout,
		Ledger: ledger.Open(h.Layout.SessionsDir),
		Index:  func(hn string) *ledger.Index { return ledger.OpenIndex(h.Layout.ProjectsDir, hn) },
		Procs:  h.Procs, Clock: h.Clock, Salt: salt, Host: h.Env,
	}
	sum := sha256.Sum256([]byte(h.ClaudeConfig))
	f.homeID = hex.EncodeToString(sum[:])[:16]
	return f
}

// session writes a synthetic session whose cwd is rel below the fake HOME.
func (f *fx) session(sid, cwd string, mod func(*claudetest.Session)) (claudetest.Session, []string) {
	f.t.Helper()
	s := claudetest.Session{SID: sid, Cwd: cwd, Lines: 16, Subagents: 1, Marker: f.marker,
		MDWrites: []string{filepath.Join(cwd, "docs", "notes.md")}, PlanSlug: "quiet-amber-river"}
	if mod != nil {
		mod(&s)
	}
	return s, f.l.WriteSession(f.t, s)
}

// slugOf returns the projects/<P> directory WriteSession used for s.
func slugOf(t *testing.T, paths []string) string {
	t.Helper()
	return filepath.Base(filepath.Dir(paths[0]))
}

func (f *fx) taint(sid string, p platform.ProcID, extra ...ledger.Event) {
	f.t.Helper()
	evs := append([]ledger.Event{{Type: ledger.TypeStart, Harness: "claude-code", SID: sid, Proc: p, Cwd: f.h.Root,
		Roots: []string{"root-acme"}, ConfigDir: f.h.ClaudeConfig, TmpDir: f.h.ClaudeTmp, Source: "startup"}}, extra...)
	for _, e := range evs {
		e.Harness, e.SID = "claude-code", sid
		if err := f.e.Ledger.Append(e); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fx) scan(s harness.Scope) []harness.Unit {
	f.t.Helper()
	units, err := f.a.Scan(context.Background(), f.e, s)
	if err != nil {
		f.t.Fatalf("Scan: %v", err)
	}
	return units
}

func find(units []harness.Unit, kind capsule.Kind, id string) (harness.Unit, bool) {
	for _, u := range units {
		if u.Kind == kind && u.UnitID == id {
			return u, true
		}
	}
	return harness.Unit{}, false
}

func rels(u harness.Unit) map[string]harness.File {
	out := map[string]harness.File{}
	for _, f := range u.Files {
		out[string(f.Base)+":"+f.Rel] = f
	}
	return out
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

var procP = platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 1_700_000_000_000_000}, PPID: 1, Exe: "/opt/claude/bin/claude"}

// I10: every file that carries the session id is sealed with the session,
// the deny-list is never sealed, and hazards are reported, never sealed.
func TestScanSessionInventoryIsFailClosed(t *testing.T) {
	f := newFx(t)
	cc, tmp := f.h.ClaudeConfig, f.h.ClaudeTmp
	_, paths := f.session(sid1, f.h.Root, nil)
	p := slugOf(t, paths)
	f.taint(sid1, procP.ID)
	f.h.Procs.Add(procP)
	f.l.WriteJob(t, "job-1", sid1, "running")
	f.l.WriteRegistry(t, 4242, sid1, f.h.Root, "idle", true)
	write(t, filepath.Join(cc, "statsig", sid1+".cache"), "x")
	write(t, filepath.Join(cc, "telemetry", "x", sid1+"-events.json"), "x")
	write(t, filepath.Join(cc, "a", "b", "c", "d", sid1+".json"), "too deep")
	write(t, filepath.Join(cc, "plugins", sid1+".json"), "denied")
	write(t, filepath.Join(cc, "settings.json"), "{}")
	write(t, filepath.Join(cc, "shell-snapshots", sid1+".sh"), "denied")
	write(t, filepath.Join(cc, "local", sid1+".json"), "installation")
	write(t, filepath.Join(cc, "projects", p, sid1+".jsonl.compact.tmp.1"), "{}\n")
	write(t, filepath.Join(cc, "projects", p, sid1, "precompact.json"), "{}")
	write(t, filepath.Join(cc, "projects", p, "sessions-index.json"), "{}")
	os.Symlink("/etc/hosts", filepath.Join(cc, "projects", p, sid1, "link"))
	hl := filepath.Join(cc, "file-history", sid1, "hard-a")
	write(t, hl, "x")
	os.Link(hl, filepath.Join(cc, "file-history", sid1, "hard-b"))
	fifo := filepath.Join(tmp, p, sid1, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	units := f.scan(harness.Scope{})
	u, ok := find(units, capsule.KindClaudeSession, sid1)
	if !ok {
		t.Fatalf("session unit missing from %d units", len(units))
	}
	key, _ := harness.UnitKeyFor(salt, capsule.KindClaudeSession, harness.ClaudeCode, f.homeID, "", sid1)
	if u.Key != key || u.VaultID != "root-acme" || len(u.RootIDs) != 1 || u.Mode != harness.GenLayered ||
		u.Harness != harness.ClaudeCode || u.Home.ID != f.homeID || u.Adopted {
		t.Fatalf("unit identity: %+v", u.Ref())
	}
	if len(u.LeaseKeys) != 1 || u.LeaseKeys[0] != key {
		t.Errorf("lease keys %v", u.LeaseKeys)
	}
	if len(u.Procs) != 1 || u.Procs[0] != procP.ID {
		t.Errorf("procs %v, want the ledger owner", u.Procs)
	}
	got := rels(u)
	for _, want := range []string{
		"claude_config:projects/" + p + "/" + sid1 + ".jsonl",
		"claude_config:projects/" + p + "/" + sid1 + ".jsonl.compact.tmp.1",
		"claude_config:projects/" + p + "/" + sid1 + "/precompact.json",
		"claude_config:file-history/" + sid1,
		"claude_config:statsig/" + sid1 + ".cache",
		"claude_config:telemetry/x/" + sid1 + "-events.json",
		"claude_config:todos/" + sid1 + "-agent-" + sid1 + ".json",
		"claude_config:tasks/" + sid1 + "/1.json",
		"claude_config:jobs/job-1/state.json",
		"claude_tmp:" + p + "/" + sid1 + "/scratchpad/notes.txt",
	} {
		if strings.HasSuffix(want, sid1) {
			continue // directories are checked below
		}
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	for k, file := range got {
		for _, bad := range []string{"plugins/", "settings.json", "shell-snapshots/", "sessions/", "local/", "a/b/c/d/", "memory/", "hard-"} {
			if strings.Contains(k, bad) {
				t.Errorf("sealed %s", k)
			}
		}
		main := strings.HasSuffix(k, "projects/"+p+"/"+sid1+".jsonl")
		sub := strings.Contains(k, "/subagents/") && strings.HasSuffix(k, ".jsonl")
		switch {
		case main && (!file.Last || file.Placement != harness.PlaceJSONLAppend || !file.Append):
			t.Errorf("main transcript: %+v", file)
		case sub && (file.Last || file.Placement != harness.PlaceJSONLAppend || !file.Append):
			t.Errorf("subagent transcript: %+v", file)
		case !main && !sub && (file.Last || file.Placement != harness.PlaceExact):
			t.Errorf("%s: %+v, want exact", k, file)
		}
		if file.Snap.Ino == 0 || file.Snap.Size < 0 {
			t.Errorf("%s: no snapshot", k)
		}
	}
	if !u.Files[len(u.Files)-1].Last {
		t.Error("the transcript is not placed last")
	}
	hz := map[string]bool{}
	for _, h := range u.Hazards {
		hz[string(h.Hazard)+":"+filepath.Base(h.Rel)] = true
	}
	for _, want := range []string{"symlink:link", "hardlink:hard-a", "hardlink:hard-b", "special:fifo"} {
		if !hz[want] {
			t.Errorf("hazard %s not reported (%v)", want, u.Hazards)
		}
	}
	dirs := map[string]bool{}
	for _, d := range u.Dirs {
		dirs[string(d.Base)+":"+d.Rel] = true
	}
	if !dirs["claude_tmp:"+p+"/"+sid1+"/started"] {
		t.Errorf("empty directory not recorded: %v", u.Dirs)
	}
	prune := strings.Join(u.Prune, ",")
	for _, want := range []string{"claude_config:projects/" + p + "/" + sid1, "claude_tmp:" + p + "/" + sid1, "claude_config:jobs/job-1"} {
		if !strings.Contains(prune, want) {
			t.Errorf("prune lacks %s: %v", want, u.Prune)
		}
	}
	if strings.Contains(prune, "claude_config:projects/"+p+",") || strings.HasSuffix(prune, "claude_config:projects/"+p) {
		t.Errorf("the shared project directory must never be pruned: %v", u.Prune)
	}
	for _, path := range u.Paths {
		if !filepath.IsAbs(path) {
			t.Errorf("relative path %s", path)
		}
	}
	// Everything sealed can be restored (Scan ⊆ Targets).
	rules, err := f.a.Targets(context.Background(), f.e, u.Ref(), sid1)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range append(append([]harness.File{}, u.Files...), u.Dirs...) {
		if !rules.Allow(file.Base, file.Rel) {
			t.Errorf("sealed %s:%s cannot be restored", file.Base, file.Rel)
		}
	}

	// Project and plan units.
	pu, ok := find(units, capsule.KindClaudeProject, p)
	if !ok || pu.VaultID != "root-acme" {
		t.Fatalf("project unit: %v %+v", ok, pu.Ref())
	}
	pf := rels(pu)
	for _, want := range []string{"claude_config:projects/" + p + "/memory/MEMORY.md", "claude_config:projects/" + p + "/sessions-index.json"} {
		if _, ok := pf[want]; !ok {
			t.Errorf("project lacks %s", want)
		}
	}
	cacheFiles := 0
	for _, file := range pu.Files {
		if file.Base == capsule.BaseClaudeCache {
			cacheFiles++
		}
	}
	if cacheFiles == 0 {
		t.Error("project lacks the MCP logs")
	}
	prules, err := f.a.Targets(context.Background(), f.e, pu.Ref(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range pu.Files {
		if !prules.Allow(file.Base, file.Rel) {
			t.Errorf("project file %s:%s cannot be restored", file.Base, file.Rel)
		}
	}
	plan, ok := find(units, capsule.KindClaudePlan, "quiet-amber-river")
	if !ok || len(plan.Files) != 2 || plan.VaultID != "root-acme" {
		t.Fatalf("plan unit: %v %+v", ok, plan.Files)
	}
	if _, ok := find(units, capsule.KindGlobalStore, "usage-data"); ok {
		t.Error("global stores scanned without Scope.Global")
	}
	// Hygiene of what a unit carries outside ciphertext: no content.
	if strings.Contains(u.Note+pu.Note, f.marker) {
		t.Error("marker in a scan note")
	}
}

func TestScanAdoptionAndUnmanagedSessions(t *testing.T) {
	f := newFx(t)
	_, inRoot := f.session(sid2, filepath.Join(f.h.Root, "sub"), nil)
	f.session(sid3, filepath.Join(f.h.HomeDir, "elsewhere"), nil)
	if _, ok := find(f.scan(harness.Scope{}), capsule.KindClaudeSession, sid2); ok {
		t.Fatal("a session without ledger or index entry was returned without adoption")
	}
	units := f.scan(harness.Scope{All: true})
	u, ok := find(units, capsule.KindClaudeSession, sid2)
	if !ok || !u.Adopted || u.VaultID != "root-acme" || len(u.Procs) != 0 {
		t.Fatalf("adoption by transcript cwd: %v %+v", ok, u.Ref())
	}
	if _, ok := find(units, capsule.KindClaudeSession, sid3); ok {
		t.Fatal("a session outside every folder was returned")
	}
	if _, ok := find(f.scan(harness.Scope{SIDs: []string{sid2}}), capsule.KindClaudeSession, sid2); !ok {
		t.Fatal("a session named by the scope was not adopted")
	}
	// The project index adopts without reading transcripts.
	x := f.e.Index("claude-code")
	if err := x.Put(ledger.Project{Harness: "claude-code", ConfigDir: f.h.ClaudeConfig, Slug: slugOf(t, inRoot), RootIDs: []string{"root-acme"}}); err != nil {
		t.Fatal(err)
	}
	if u, ok := find(f.scan(harness.Scope{}), capsule.KindClaudeSession, sid2); !ok || !u.Adopted {
		t.Fatal("index adoption failed")
	}
	// Scope filters.
	if units := f.scan(harness.Scope{RootIDs: []string{"root-other"}}); len(units) != 0 {
		t.Fatalf("other root: %d units", len(units))
	}
	for _, u := range f.scan(harness.Scope{Kinds: []capsule.Kind{capsule.KindClaudeProject}}) {
		if u.Kind != capsule.KindClaudeProject {
			t.Fatalf("kind filter returned %s", u.Kind)
		}
	}
	// A root that is no longer protected does not attribute sessions.
	f.taint(sid1, procP.ID)
	f.session(sid1, f.h.Root, nil)
	f.e.Cfg.Roots = nil
	if units := f.scan(harness.Scope{All: true}); len(units) != 0 {
		t.Fatalf("units without any protected root: %d", len(units))
	}
}

func TestScanGlobalStoresAndErrors(t *testing.T) {
	f := newFx(t)
	write(t, filepath.Join(f.h.ClaudeConfig, "usage-data", "a.json"), "x")
	write(t, filepath.Join(f.h.ClaudeConfig, "feedback", "drafts", "d.txt"), "x")
	write(t, filepath.Join(f.h.ClaudeConfig, "feedback", "other.txt"), "x")
	units := f.scan(harness.Scope{Global: true})
	for _, store := range []string{"usage-data", "feedback/drafts"} {
		u, ok := find(units, capsule.KindGlobalStore, store)
		if !ok || u.VaultID != "global" || len(u.RootIDs) != 0 || len(u.Files) != 1 {
			t.Fatalf("store %s: %v %+v", store, ok, u)
		}
		rules, err := f.a.Targets(context.Background(), f.e, u.Ref(), store)
		if err != nil || !rules.Allow(u.Files[0].Base, u.Files[0].Rel) {
			t.Fatalf("store %s not restorable: %v", store, err)
		}
	}
	noSalt := f.e
	noSalt.Salt = nil
	if _, err := f.a.Scan(context.Background(), noSalt, harness.Scope{}); err == nil {
		t.Fatal("Scan without a salt succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.a.Scan(ctx, f.e, harness.Scope{}); err == nil {
		t.Fatal("cancelled Scan succeeded")
	}
	if os.Getuid() != 0 {
		os.Chmod(f.h.ClaudeConfig, 0o000)
		_, err := f.a.Scan(context.Background(), f.e, harness.Scope{})
		os.Chmod(f.h.ClaudeConfig, 0o700)
		if err == nil {
			t.Fatal("an unreadable home was scanned as empty (never treat EACCES as missing)")
		}
	}
}

func evidence(t *testing.T, f *fx, u harness.Unit) map[live.Reason][]live.Evidence {
	t.Helper()
	evs, err := f.a.Probe(context.Background(), f.e, u)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	out := map[live.Reason][]live.Evidence{}
	for _, e := range evs {
		out[e.Reason] = append(out[e.Reason], e)
	}
	return out
}

func sessionUnit(t *testing.T, f *fx, sid string) harness.Unit {
	t.Helper()
	u, ok := find(f.scan(harness.Scope{All: true}), capsule.KindClaudeSession, sid)
	if !ok {
		t.Fatalf("no unit for %s", sid)
	}
	return u
}

// E2 with D18's start check, LIVE-3 (pid reuse), LIVE-5 (startedAt
// missing), LIVE-9 (half-written registry).
func TestProbeRegistry(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	u := sessionUnit(t, f, sid1)
	start := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	proc := platform.ProcInfo{ID: platform.ProcID{PID: 300, StartUS: start.UnixMicro()}, PPID: 1, Exe: "/opt/claude/bin/claude"}
	f.h.Procs.Add(proc)
	if ev := evidence(t, f, u); len(ev) != 0 {
		t.Fatalf("no registry: %v", ev)
	}
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 300, SessionID: sid1, Cwd: f.h.Root, StartedAt: start.Add(time.Second), Valid: true})
	ev := evidence(t, f, u)
	if len(ev[live.ReasonRegistry]) != 1 || ev[live.ReasonRegistry][0].Proc != proc.ID || ev[live.ReasonRegistry][0].Weak {
		t.Fatalf("registry evidence: %v", ev)
	}
	// LIVE-3: the pid now belongs to a newer process.
	f.h.Procs.Reuse(300, start.Add(time.Minute).UnixMicro(), "/bin/sh")
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistry]) != 0 {
		t.Fatalf("reused pid kept the session live: %v", ev)
	}
	// A spoofed entry naming a live non-Claude process: live but weak (SEC-20).
	shell := platform.ProcInfo{ID: platform.ProcID{PID: 301, StartUS: start.UnixMicro()}, PPID: 1, Exe: "/bin/zsh"}
	f.h.Procs.Add(shell)
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 301, SessionID: sid1, StartedAt: start, Valid: true})
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistry]) != 1 || !ev[live.ReasonRegistry][0].Weak {
		t.Fatalf("spoofed registry: %v", ev)
	}
	os.Remove(filepath.Join(f.h.ClaudeConfig, "sessions", "301.json"))
	// LIVE-5: no startedAt; the file was written after the process started.
	f.h.Procs.Add(proc)
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 300, SessionID: sid1, Valid: true})
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistry]) != 1 {
		t.Fatalf("startedAt missing: %v", ev)
	}
	old := start.Add(-time.Hour)
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 300, SessionID: sid1, Mtime: old, Valid: true})
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistry]) != 0 {
		t.Fatalf("a registry file older than the process names another incarnation: %v", ev)
	}
	// LIVE-9: half-written entry of a live process whose cwd is the folder.
	f.l.WriteRegistry(t, 300, sid1, f.h.Root, "busy", false)
	f.h.Procs.SetCwd(300, f.h.Root)
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistryIO]) != 1 {
		t.Fatalf("half-written registry: %v", ev)
	}
	f.h.Procs.SetCwd(300, filepath.Join(f.h.HomeDir, "unrelated"))
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistryIO]) != 0 {
		t.Fatalf("half-written registry of a process elsewhere: %v", ev)
	}
	f.h.Procs.SetCwd(300, "")
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistryIO]) != 1 {
		t.Fatalf("half-written registry, unknown cwd: %v", ev)
	}
	// An unreadable process table is evidence.
	f.h.Procs.SetErr(fakeplatform.OpLookup, errors.New("denied"))
	if ev := evidence(t, f, u); len(ev[live.ReasonRegistryIO]) == 0 {
		t.Fatalf("Lookup failure: %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpLookup, nil)
	// The process exited: nothing.
	f.h.Procs.Exit(300, false)
	if ev := evidence(t, f, u); len(ev) != 0 {
		t.Fatalf("after exit: %v", ev)
	}
}

// LIVE-8 (D25): a background session is live while its job record is not
// verifiably stopped; a record of unknown schema is live (weak).
func TestProbeJobs(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	f.l.WriteJob(t, "job-1", sid1, "running")
	u := sessionUnit(t, f, sid1)
	if ev := evidence(t, f, u); len(ev[live.ReasonJob]) != 1 {
		t.Fatalf("running job: %v", ev)
	}
	f.l.WriteJob(t, "job-1", sid1, "stopped")
	if ev := evidence(t, f, u); len(ev[live.ReasonJob]) != 0 {
		t.Fatalf("stopped job: %v", ev)
	}
	f.l.WriteJob(t, "job-1", sid1, "running") // restarted
	if ev := evidence(t, f, u); len(ev[live.ReasonJob]) != 1 {
		t.Fatalf("restarted job: %v", ev)
	}
	f.l.WriteJob(t, "job-2", sid2, "running") // another session's job
	write(t, filepath.Join(f.h.ClaudeConfig, "jobs", "job-3", "state.json"), "{garbage")
	ev := evidence(t, f, u)
	if len(ev[live.ReasonJob]) != 2 {
		t.Fatalf("jobs: %v", ev)
	}
	weak := 0
	for _, e := range ev[live.ReasonJob] {
		if e.Weak {
			weak++
		}
	}
	if weak != 1 {
		t.Fatalf("unknown-schema job must be weak evidence: %v", ev[live.ReasonJob])
	}
}

// D20: after /clear the old session is non-current for the live process
// (warm); E6: a descriptor below the session's tmp dir; E8: a live fork.
func TestProbeWarmOpenFilesAndForks(t *testing.T) {
	f := newFx(t)
	_, paths := f.session(sid1, f.h.Root, nil)
	p := slugOf(t, paths)
	f.h.Procs.Add(procP)
	f.taint(sid1, procP.ID, ledger.Event{Type: ledger.TypeEnd, Proc: procP.ID, Reason: "clear"})
	f.taint(sid2, procP.ID)
	u := sessionUnit(t, f, sid1)
	if len(u.Procs) != 0 {
		t.Fatalf("a /clear'ed session still lists its process as owner: %v", u.Procs)
	}
	ev := evidence(t, f, u)
	if len(ev[live.ReasonWarm]) != 1 || ev[live.ReasonWarm][0].Proc != procP.ID {
		t.Fatalf("warm: %v", ev)
	}
	f.h.Procs.Exit(procP.ID.PID, false)
	if ev := evidence(t, f, u); len(ev[live.ReasonWarm]) != 0 {
		t.Fatalf("warm after exit: %v", ev)
	}

	bash := platform.ProcInfo{ID: platform.ProcID{PID: 500, StartUS: 7}, PPID: 1, Exe: "/bin/bash"}
	f.h.Procs.Add(bash)
	f.h.Procs.SetOpenFiles(500, filepath.Join(f.h.ClaudeTmp, p, sid1, "tasks", "x.output"))
	if ev := evidence(t, f, u); len(ev[live.ReasonOpenFD]) != 1 || ev[live.ReasonOpenFD][0].Proc != bash.ID {
		t.Fatalf("open descriptor: %v", ev)
	}
	f.h.Procs.SetOpenFiles(500)
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, errors.New("lsof missing"))
	if ev := evidence(t, f, u); len(ev[live.ReasonOpenFD]) != 1 {
		t.Fatalf("open-file check failure must be live (HA9): %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, nil)

	// sid3 is live (registry) and its transcript references sid1.
	_, p3 := f.session(sid3, f.h.Root, func(s *claudetest.Session) { s.PlanSlug = "" })
	fh, _ := os.OpenFile(p3[0], os.O_WRONLY|os.O_APPEND, 0)
	fh.WriteString(`{"type":"fork-context-ref","sessionId":"` + sid3 + `","parentSessionId":"` + sid1 + `"}` + "\n")
	fh.Close()
	fork := platform.ProcInfo{ID: platform.ProcID{PID: 600, StartUS: time.Now().Add(-time.Minute).UnixMicro()}, PPID: 1, Exe: "/opt/claude/bin/claude"}
	f.h.Procs.Add(fork)
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 600, SessionID: sid3, StartedAt: time.Now(), Valid: true})
	if ev := evidence(t, f, u); len(ev[live.ReasonForkParent]) != 1 {
		t.Fatalf("fork parent: %v", ev)
	}
}

// D47: project units are live while Claude runs in the folder, in the git
// repository containing it, or with an unknown cwd (fakeplatform SetCwd).
func TestProbeProjectCwdRules(t *testing.T) {
	f := newFx(t)
	_, paths := f.session(sid1, f.h.Root, nil)
	f.taint(sid1, platform.ProcID{})
	p := slugOf(t, paths)
	pu, ok := find(f.scan(harness.Scope{}), capsule.KindClaudeProject, p)
	if !ok {
		t.Fatal("no project unit")
	}
	if ev := evidence(t, f, pu); len(ev) != 0 {
		t.Fatalf("no Claude process: %v", ev)
	}
	c := platform.ProcInfo{ID: platform.ProcID{PID: 700, StartUS: 1}, PPID: 1, Exe: "/Users/x/.local/share/claude/versions/2.1.329", Comm: "2.1.329"}
	f.h.Procs.Add(c)
	other := platform.ProcInfo{ID: platform.ProcID{PID: 701, StartUS: 1}, PPID: 1, Exe: "/usr/bin/vim"}
	f.h.Procs.Add(other)
	f.h.Procs.SetCwd(701, f.h.Root) // not Claude: ignored
	for cwd, want := range map[string]bool{
		filepath.Join(f.h.Root, "src"):              true,
		filepath.Join(f.h.HomeDir, "work", "other"): false,
		"": true, // unknown
	} {
		f.h.Procs.SetCwd(700, cwd)
		ev := evidence(t, f, pu)
		if got := len(ev[live.ReasonProcess]) == 1; got != want {
			t.Errorf("cwd %q: %v, want live=%v", cwd, ev, want)
		}
		for _, e := range ev[live.ReasonProcess] {
			if !e.Weak {
				t.Errorf("process evidence must be weak (S14): %+v", e)
			}
		}
	}
	// The folder sits in a git repository rooted above it: memory is shared
	// per repository (HA14), so Claude anywhere in the repository counts.
	if err := os.MkdirAll(filepath.Join(f.h.HomeDir, "work", ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.h.Procs.SetCwd(700, filepath.Join(f.h.HomeDir, "work", "other"))
	if ev := evidence(t, f, pu); len(ev[live.ReasonProcess]) != 1 {
		t.Fatalf("cwd in the repository: %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpCwd, errors.New("denied"))
	if ev := evidence(t, f, pu); len(ev[live.ReasonProcess]) != 1 {
		t.Fatalf("cwd unreadable: %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpCwd, nil)
	f.h.Procs.SetErr(fakeplatform.OpList, errors.New("denied"))
	if ev := evidence(t, f, pu); len(ev[live.ReasonUnknown]) != 1 {
		t.Fatalf("process table unreadable: %v", ev)
	}
}

func TestProbePlanAndGlobal(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	f.taint(sid1, procP.ID)
	units := f.scan(harness.Scope{Global: true})
	plan, ok := find(units, capsule.KindClaudePlan, "quiet-amber-river")
	if !ok {
		t.Fatal("no plan unit")
	}
	if ev := evidence(t, f, plan); len(ev) != 0 {
		t.Fatalf("no live session: %v", ev)
	}
	f.h.Procs.Add(procP) // the ledger owner is alive
	if ev := evidence(t, f, plan); len(ev[live.ReasonPlanSlug]) != 1 {
		t.Fatalf("live session references the slug: %v", ev)
	}
	write(t, filepath.Join(f.h.ClaudeConfig, "usage-data", "u.json"), "x")
	units = f.scan(harness.Scope{Global: true})
	g, ok := find(units, capsule.KindGlobalStore, "usage-data")
	if !ok {
		t.Fatal("no global unit")
	}
	if ev := evidence(t, f, g); len(ev[live.ReasonProcess]) != 1 {
		t.Fatalf("a Claude process runs: %v", ev)
	}
	f.h.Procs.Exit(procP.ID.PID, false)
	if ev := evidence(t, f, g); len(ev) != 0 {
		t.Fatalf("no Claude process: %v", ev)
	}
	if evs, err := f.a.Probe(context.Background(), harness.Env{}, g); err != nil || len(evs) == 0 {
		t.Fatalf("Probe without a process table must be live: %v %v", evs, err)
	}
}

// End to end with the liveness engine: LIVE-1 at the adapter level.
func TestSessionLivenessEndToEnd(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	f.h.Procs.Add(procP)
	f.taint(sid1, procP.ID, ledger.Event{Type: ledger.TypeEnd, Proc: procP.ID, Reason: "other"})
	engine := &live.Engine{Procs: f.h.Procs, Clock: f.h.Clock, LeasesDir: f.h.Layout.LeasesDir,
		Observer: live.NewObserver(f.h.Clock), Quiet: 120 * time.Second, HoldCap: 24 * time.Hour}
	decide := func() live.Verdict {
		u := sessionUnit(t, f, sid1)
		extra, err := f.a.Probe(context.Background(), f.e, u)
		if err != nil {
			t.Fatal(err)
		}
		v, err := engine.Decide(context.Background(), live.Subject{Key: u.Key, Paths: u.Paths, Procs: u.Procs, LeaseKeys: u.LeaseKeys}, extra)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	decide()
	f.h.Clock.Advance(130 * time.Second)
	if v := decide(); !v.Live {
		t.Fatalf("ended session with a live process: %+v", v)
	}
	f.h.Procs.Exit(procP.ID.PID, false)
	if v := decide(); v.Live {
		t.Fatalf("after the process exited: %+v", v)
	}
}

// SPEC §11.2: targets per kind, from trusted context only.
func TestTargetsPerKind(t *testing.T) {
	f := newFx(t)
	_, paths := f.session(sid1, f.h.Root, nil)
	p := slugOf(t, paths)
	ref := func(k capsule.Kind) harness.UnitRef {
		return harness.UnitRef{Harness: harness.ClaudeCode, Kind: k, HomeID: f.homeID, RootIDs: []string{"root-acme"}}
	}
	ctx := context.Background()
	rules, err := f.a.Targets(ctx, f.e, ref(capsule.KindClaudeSession), sid1)
	if err != nil {
		t.Fatal(err)
	}
	if rules.Mode != harness.GenLayered || rules.Bases[capsule.BaseClaudeConfig] != f.h.ClaudeConfig || rules.Bases[capsule.BaseClaudeTmp] != f.h.ClaudeTmp {
		t.Fatalf("bases %v mode %s", rules.Bases, rules.Mode)
	}
	allow := map[string]bool{
		"claude_config:projects/" + p + "/" + sid1 + ".jsonl":                 true,
		"claude_config:projects/other-project/" + sid1 + ".jsonl":             true, // resumed from another folder
		"claude_config:projects/" + p + "/" + sid1 + "/subagents/agent.jsonl": true,
		"claude_config:file-history/" + sid1 + "/abc@v1":                      true,
		"claude_config:session-env/" + sid1 + "/hook.sh":                      true,
		"claude_config:todos/" + sid1 + "-agent-" + sid1 + ".json":            true,
		"claude_config:debug/" + sid1 + ".txt":                                true,
		"claude_config:jobs/job-1/state.json":                                 true,
		"claude_tmp:" + p + "/" + sid1 + "/tasks/x.output":                    true,
		"claude_config:projects/" + p + "/memory/MEMORY.md":                   false,
		"claude_config:session-env/" + sid2 + "/hook.sh":                      false,
		"claude_config:projects/" + p + "/" + sid2 + ".jsonl":                 false,
		"claude_config:settings.json":                                         false,
		"claude_config:plugins/" + sid1 + ".json":                             false,
		"claude_config:sessions/" + sid1 + ".json":                            false,
		"claude_config:shell-snapshots/" + sid1 + ".sh":                       false,
		"claude_config:a/b/c/d/" + sid1 + ".json":                             false,
		"claude_config:../" + sid1 + ".json":                                  false,
		"claude_config:/etc/" + sid1:                                          false,
		"claude_config:file-history/./" + sid1:                                false,
		"claude_config:":                                                      false,
		"claude_tmp:unknown-project/" + sid1 + "/x":                           false,
		"claude_tmp:" + sid1 + "/x":                                           false,
		"root:" + sid1 + ".md":                                                false,
		"codex_home:" + sid1 + ".jsonl":                                       false,
	}
	if runtime.GOOS == "darwin" {
		allow["claude_config:Plugins/"+sid1+".json"] = false
		allow["claude_config:SETTINGS.json"] = false
	}
	for k, want := range allow {
		base, rel, _ := strings.Cut(k, ":")
		if got := rules.Allow(capsule.BaseID(base), rel); got != want {
			t.Errorf("session Allow(%s) = %v, want %v", k, got, want)
		}
	}
	if pl := rules.Policy(capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "projects/" + p + "/" + sid1 + ".jsonl"}); pl != harness.PlaceJSONLAppend {
		t.Errorf("transcript policy %s", pl)
	}
	if pl := rules.Policy(capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "projects/" + p + "/" + sid1 + "/subagents/a.jsonl"}); pl != harness.PlaceJSONLAppend {
		t.Errorf("subagent policy %s", pl)
	}
	if pl := rules.Policy(capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "todos/" + sid1 + ".json"}); pl != harness.PlaceExact {
		t.Errorf("todo policy %s", pl)
	}

	project, _ := f.a.Targets(ctx, f.e, ref(capsule.KindClaudeProject), p)
	for k, want := range map[string]bool{
		"claude_config:projects/" + p + "/memory/MEMORY.md":    true,
		"claude_config:projects/" + p + "/sessions-index.json": true,
		"claude_cache:" + p + "/mcp-logs-x/a.jsonl":            true,
		"claude_config:projects/other/memory/MEMORY.md":        false,
		"claude_config:projects/" + p + "/" + sid1 + ".jsonl":  false,
		"claude_config:projects/" + p + "/unknown/file":        false,
		"claude_cache:other/x":                                 false,
	} {
		base, rel, _ := strings.Cut(k, ":")
		if got := project.Allow(capsule.BaseID(base), rel); got != want {
			t.Errorf("project Allow(%s) = %v, want %v", k, got, want)
		}
	}
	plan, _ := f.a.Targets(ctx, f.e, ref(capsule.KindClaudePlan), "quiet-amber-river")
	for rel, want := range map[string]bool{
		"plans/quiet-amber-river.md":         true,
		"plans/quiet-amber-river-agent-1.md": true,
		"plans/quiet-amber.md":               false,
		"plans/quiet-amber-river.txt":        false,
		"plans/sub/quiet-amber-river.md":     false,
	} {
		if got := plan.Allow(capsule.BaseClaudeConfig, rel); got != want {
			t.Errorf("plan Allow(%s) = %v, want %v", rel, got, want)
		}
	}
	hist, _ := f.a.Targets(ctx, f.e, ref(capsule.KindClaudeHistory), "root-acme")
	if !hist.Allow(capsule.BaseClaudeConfig, "history.jsonl") || !hist.Allow(capsule.BaseClaudeConfig, "paste-cache/abc.txt") ||
		hist.Allow(capsule.BaseClaudeConfig, "paste-cache/a/b") || hist.Allow(capsule.BaseClaudeConfig, ".claude.json") {
		t.Error("history targets")
	}
	if hist.Policy(capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "history.jsonl"}) != harness.PlaceLineUnion {
		t.Error("history.jsonl must be a line union")
	}

	// Refusals: unregistered home, bad unit ids, foreign kinds.
	bad := ref(capsule.KindClaudeSession)
	bad.HomeID = "ffffffffffffffff"
	if _, err := f.a.Targets(ctx, f.e, bad, sid1); !errors.Is(err, harness.ErrUnregistered) {
		t.Errorf("unregistered home: %v", err)
	}
	for kind, id := range map[capsule.Kind]string{
		capsule.KindClaudeSession: "not-a-uuid", capsule.KindClaudeProject: "a/b", capsule.KindClaudePlan: "../x",
		capsule.KindGlobalStore: "secrets", capsule.KindCodexHome: "root-acme", capsule.KindClaudeHistory: "root-other",
	} {
		if _, err := f.a.Targets(ctx, f.e, ref(kind), id); !errors.Is(err, harness.ErrUnitKey) {
			t.Errorf("%s %q: %v", kind, id, err)
		}
	}
	codexRef := ref(capsule.KindClaudeSession)
	codexRef.Harness = harness.Codex
	if _, err := f.a.Targets(ctx, f.e, codexRef, sid1); err == nil {
		t.Error("a Codex ref was accepted")
	}
	// An unsafe tmp dir is never a target (S7).
	os.Chmod(f.h.ClaudeTmp, 0o755)
	defer os.Chmod(f.h.ClaudeTmp, 0o700)
	unsafe, _ := f.a.Targets(ctx, f.e, ref(capsule.KindClaudeSession), sid1)
	if _, ok := unsafe.Bases[capsule.BaseClaudeTmp]; ok || unsafe.Allow(capsule.BaseClaudeTmp, p+"/"+sid1+"/x") {
		t.Error("a group-readable tmp dir is still a restore target")
	}
}

func TestPlanLaunch(t *testing.T) {
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "claude")
	write(t, bin, "#!/bin/sh\n")
	os.Chmod(bin, 0o700)
	hc := f.e.Cfg.Harness["claude-code"]
	hc.Bin = bin
	f.e.Cfg.Harness["claude-code"] = hc
	ctx := context.Background()
	settings := claude.SettingsJSON(f.e.Cfg.Policy)

	plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Argv, " ") != bin+" --settings "+settings {
		t.Errorf("argv = %q", plan.Argv)
	}
	if plan.Mode != harness.LaunchInteractive || len(plan.Roots) != 1 || plan.Roots[0].ID != "root-acme" ||
		strings.Join(plan.Env, " ") != "CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0" || plan.Confirm != "" {
		t.Errorf("plan = %+v", plan)
	}
	if plan.HookCheck.Event != "SessionStart" || plan.HookCheck.Within != 10*time.Second {
		t.Errorf("hook check %+v", plan.HookCheck)
	}
	if len(plan.Sync) != 1 || plan.Sync[0].Kind != capsule.KindClaudeProject || plan.Sync[0].ProjectDir != f.h.Root {
		t.Errorf("sync %+v", plan.Sync)
	}
	if len(plan.Background) != 1 || plan.Background[0].Recent != 5 || plan.Background[0].MaxAge != 28*24*time.Hour ||
		plan.Background[0].MaxBytes != 1<<30 || plan.Background[0].RootID != "root-acme" {
		t.Errorf("background %+v (D38, D14: cleanupPeriodDays 30 − 2)", plan.Background)
	}
	if len(plan.SealScope.RootIDs) != 1 {
		t.Errorf("seal scope %+v", plan.SealScope)
	}

	// Resume by sid: restored first, by key, with the D14 clamp.
	key, _ := harness.UnitKeyFor(salt, capsule.KindClaudeSession, harness.ClaudeCode, f.homeID, "", sid1)
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "--resume", sid1})
	if plan.Resume.Kind != harness.ResumeSID || len(plan.Sync) != 2 || len(plan.Sync[0].Keys) != 1 || plan.Sync[0].Keys[0] != key ||
		!plan.Sync[0].MtimeNow || plan.Lease[0] != key || plan.SealScope.SIDs[0] != sid1 {
		t.Errorf("resume plan %+v", plan)
	}
	// The session is open in another terminal: C7.twice, opened as a fork.
	start := time.Now().Add(-time.Minute)
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 900, StartUS: start.UnixMicro()}, PPID: 1, Exe: "/opt/claude/bin/claude"})
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 900, SessionID: sid1, StartedAt: start, Valid: true})
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "-r", sid1})
	if plan.Confirm != "C7.twice" || !plan.Resume.Fork || plan.Argv[len(plan.Argv)-1] != "--fork-session" {
		t.Errorf("twice: %+v", plan)
	}
	// The user's own --settings wins; --bare asks first.
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "--settings", "{}", "--bare"})
	if strings.Join(plan.Argv, " ") != bin+" --settings {} --bare" || plan.Confirm != "C9.bare" {
		t.Errorf("user settings / bare: %+v", plan)
	}
	// Passthrough and direct modes.
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "--version"})
	if plan.Mode != harness.LaunchPassthrough || strings.Join(plan.Argv, " ") != bin+" --version" || len(plan.Sync) != 0 || len(plan.Env) != 0 {
		t.Errorf("passthrough: %+v", plan)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "-p", "hello"})
	if plan.Mode != harness.LaunchDirect || plan.Argv[1] != "--settings" {
		t.Errorf("direct: %+v", plan)
	}
	// Outside every folder: nothing is injected or restored; --add-dir of a
	// folder makes the launch managed (SEC-18).
	outside := filepath.Join(f.h.HomeDir, "elsewhere")
	plan, _ = f.a.PlanLaunch(ctx, f.e, outside, []string{"claude"})
	if len(plan.Roots) != 0 || len(plan.Argv) != 1 || len(plan.Sync)+len(plan.Background) != 0 {
		t.Errorf("outside: %+v", plan)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, outside, []string{"claude", "--add-dir", f.h.Root})
	if len(plan.Roots) != 1 || plan.Argv[1] != "--settings" {
		t.Errorf("--add-dir: %+v", plan)
	}
	// Picker and continue.
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "--resume"})
	if plan.Resume.Kind != harness.ResumePicker || len(plan.Sync) != 2 || plan.Sync[0].Recent != 5 || len(plan.Background) != 0 {
		t.Errorf("picker: %+v", plan)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "-c"})
	if plan.Resume.Kind != harness.ResumeContinue || !plan.Sync[0].Newest || plan.Sync[0].ProjectDir != f.h.Root {
		t.Errorf("continue: %+v", plan)
	}
	if _, err := f.a.PlanLaunch(ctx, f.e, "relative", []string{"claude"}); err == nil {
		t.Error("relative cwd accepted")
	}
	if _, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, nil); err == nil {
		t.Error("empty argv accepted")
	}
}

func TestHomesMarkdownAndDescribe(t *testing.T) {
	f := newFx(t)
	note := filepath.Join(f.h.Root, "docs", "notes.md")
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	f.session(sid1, f.h.Root, func(s *claudetest.Session) { s.ModTime = at })
	f.taint(sid1, procP.ID)
	hs, err := f.a.Homes(context.Background(), f.e)
	if err != nil || len(hs) != 1 || hs[0].ID != f.homeID || hs[0].Bases[capsule.BaseClaudeConfig] != f.h.ClaudeConfig {
		t.Fatalf("Homes = %+v, %v (registered and default home are the same)", hs, err)
	}
	// A config dir only the ledger has seen is a home too (not registered).
	seen := filepath.Join(f.h.Dir, "other-claude")
	os.MkdirAll(seen, 0o700)
	f.e.Ledger.Append(ledger.Event{Type: ledger.TypeStart, Harness: "claude-code", SID: sid2, ConfigDir: seen})
	hs, _ = f.a.Homes(context.Background(), f.e)
	if len(hs) != 2 {
		t.Fatalf("ledger home missing: %+v", hs)
	}
	u := sessionUnit(t, f, sid1)
	md, err := f.a.MarkdownPaths(context.Background(), f.e, u)
	if err != nil || len(md) != 1 || md[0] != note {
		t.Fatalf("MarkdownPaths = %v %v", md, err)
	}
	title, last, err := f.a.Describe(context.Background(), f.e, u)
	if err != nil || !strings.Contains(title, "claudetest session title") || !last.Equal(at) {
		t.Fatalf("Describe = %q %v %v", title, last, err)
	}
	if strings.Contains(strings.Join(u.Paths, ""), f.marker) {
		t.Fatal("marker in unit paths")
	}
}

// Two config dirs of one user share $TMP and $CACHE: every session or
// project directory found there belongs to exactly one home (the one with
// the session's files, else the one its ledger names).
func TestSharedTmpAndCacheBelongToOneHome(t *testing.T) {
	f := newFx(t)
	_, paths := f.session(sid1, f.h.Root, nil)
	p := slugOf(t, paths)
	f.taint(sid1, procP.ID)
	// A second home, known from the ledger, using the same tmp and cache.
	other := filepath.Join(f.h.Dir, "claude-work")
	ol := &claudetest.Layout{ConfigDir: other, TmpDir: f.h.ClaudeTmp, CacheDir: f.h.ClaudeCache}
	ol.WriteSession(t, claudetest.Session{SID: sid2, Cwd: filepath.Join(f.h.Root, "w"), Lines: 12})
	f.e.Ledger.Append(ledger.Event{Type: ledger.TypeStart, Harness: "claude-code", SID: sid2, Proc: procP.ID,
		Cwd: f.h.Root, Roots: []string{"root-acme"}, ConfigDir: other, TmpDir: f.h.ClaudeTmp})
	// A tmp-only session the ledger attributes to the second home.
	write(t, filepath.Join(f.h.ClaudeTmp, p, sid3, "tasks", "t.output"), "x")
	f.e.Ledger.Append(ledger.Event{Type: ledger.TypeStart, Harness: "claude-code", SID: sid3, Proc: procP.ID,
		Cwd: f.h.Root, Roots: []string{"root-acme"}, ConfigDir: other})

	units := f.scan(harness.Scope{})
	homesOf := map[string][]string{}
	tmpFiles := map[string]int{}
	for _, u := range units {
		for _, file := range u.Files {
			if file.Base == capsule.BaseClaudeTmp || file.Base == capsule.BaseClaudeCache {
				k := string(file.Base) + ":" + file.Rel
				tmpFiles[k]++
				homesOf[k] = append(homesOf[k], u.Home.ID)
			}
		}
	}
	if len(tmpFiles) == 0 {
		t.Fatal("no tmp or cache files were inventoried")
	}
	for k, n := range tmpFiles {
		if n != 1 {
			t.Errorf("%s is in %d units (homes %v)", k, n, homesOf[k])
		}
	}
	s1, ok := find(units, capsule.KindClaudeSession, sid1)
	if !ok || s1.Home.ID != f.homeID {
		t.Fatalf("sid1 must stay with its own home: %+v", s1.Ref())
	}
	s3, ok := find(units, capsule.KindClaudeSession, sid3)
	if !ok || s3.Home.ID == f.homeID {
		t.Fatalf("a tmp-only session goes to the home its ledger names: %v %+v", ok, s3.Ref())
	}
}
