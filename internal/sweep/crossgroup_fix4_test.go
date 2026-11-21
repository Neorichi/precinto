//go:build crossgroup

package sweep_test

// Regression tests of the fix-4 wave over the real implementations of the
// other groups (DATA-1…DATA-10).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/testkit"
)

// D83 (DATA-2): md = "ledger"; the unlock restores the folder's notes but
// not the session that wrote them; the next lock seals the note again
// (unchanged, no new generation) and the marker is back.
func TestRestoredNoteIsSealedAtTheNextLock(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	s.session(t, xSID, "")
	p := filepath.Join(s.h.Root, "docs", "plan.md")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("# plan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := s.clock.Now().Add(-time.Hour)
	_ = os.Chtimes(p, old, old)
	if err := s.e.Harness.Ledger.Append(ledger.Event{Type: ledger.TypeMarkdown, Harness: string(harness.ClaudeCode), SID: xSID, Path: p, Roots: []string{xRoot}}); err != nil {
		t.Fatal(err)
	}
	_ = s.e.Harness.Ledger.Append(ledger.Event{Type: ledger.TypeEnd, Harness: string(harness.ClaudeCode), SID: xSID, Reason: "other"})
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil || resultOfKind(rep, capsule.KindMarkdown, sweep.OutSealed) == nil {
		t.Fatalf("lock 1 %+v %v", rep, err)
	}
	root, _ := s.e.Cfg.RootByID(xRoot)
	rep, err = sweep.RestoreMarkdown(ctx, s.e, s.keys, root)
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore notes %+v %v", rep, err)
	}
	sum, err := sweep.PlaintextSummary(ctx, s.e)
	if err != nil {
		t.Fatal(err)
	}
	notes := 0
	for _, ps := range sum {
		notes += ps.ByReason["notes"]
	}
	if notes != 1 {
		t.Fatalf("restored note not in the plaintext summary: %+v", sum)
	}
	s.clock.Advance(10 * time.Minute)
	rep, err = sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil || resultOfKind(rep, capsule.KindMarkdown, sweep.OutUnchanged) == nil {
		t.Fatalf("lock 2 %+v %v", rep, err)
	}
	if _, err := os.Lstat(p); err == nil {
		t.Fatal("the restored note is still plaintext in the locked folder")
	}
	if _, err := sweep.ParseMarker(p + ".precinto"); err != nil {
		t.Fatalf("marker: %v", err)
	}
}

// D84 (DATA-4): a classic fragment Claude appended while the transcript
// was sealed merges at restore when nothing is live (real Claude
// adapter), every file is placed, the next seal is a successor and a
// later restore returns the whole conversation.
func TestFragmentMergesWhenNothingIsLive(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := filterSID(s.session(t, xSID, ""), xSID)
	orig := contents(t, paths)
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("seal %+v", rep.Units)
	}
	ref := []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: res.Unit}}
	l := claudetest.New(t, s.h.Dir)
	frag := l.AppendFragment(t, claudetest.Session{SID: xSID, Cwd: s.h.Root}, 2)
	fragBytes, _ := os.ReadFile(frag)
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref})
	if err != nil || rep.Count(sweep.OutMerged) != 1 {
		t.Fatalf("restore %+v %v", rep.Units, err)
	}
	for p := range orig {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("not placed: %s", p)
		}
	}
	got, _ := os.ReadFile(frag)
	if len(got) < len(orig[frag])+len(fragBytes) {
		t.Fatalf("transcript %d bytes, want the capsule (%d) plus the fragment (%d)", len(got), len(orig[frag]), len(fragBytes))
	}
	rep, err = sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed); r == nil || r.Lineage != capsule.LineageSuccessor {
		t.Fatalf("next lock %+v", rep.Units)
	}
	if _, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref}); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(frag); string(again) != string(got) {
		t.Fatalf("restore after the next lock: %d bytes, want %d", len(again), len(got))
	}
}

// D84: a session that turns live between the first liveness check and
// placement (a resumed Claude process the registry names) is never
// merged into: nothing of the unit is placed and the fragment stays.
func TestFragmentOfASessionLiveAtPlacementIsUntouched(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := filterSID(s.session(t, xSID, ""), xSID)
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("seal %+v", rep.Units)
	}
	l := claudetest.New(t, s.h.Dir)
	frag := l.AppendFragment(t, claudetest.Session{SID: xSID, Cwd: s.h.Root}, 2)
	before, _ := os.ReadFile(frag)
	const pid = 5151
	rep, _ = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{
		Units: []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: res.Unit}},
		BeforePlace: func(string) error {
			s.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: time.Now().Add(-time.Second).UnixMicro()},
				PPID: 1, UID: os.Getuid(), State: platform.StateRunning, Exe: "/usr/local/bin/claude"})
			l.WriteRegistry(t, pid, xSID, s.h.Root, "busy", true)
			return nil
		},
	})
	if rep.Count(sweep.OutLive) != 1 {
		t.Fatalf("restore %+v", rep.Units)
	}
	if after, _ := os.ReadFile(frag); string(after) != string(before) {
		t.Fatal("merged into a live session")
	}
	for _, p := range paths {
		if p == frag {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("placed although the unit was live: %s", p)
		}
	}
}

// appendUserLine appends one Claude record to a transcript.
func appendUserLine(t *testing.T, p, uuid string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(`{"type":"user","uuid":"` + uuid + `","sessionId":"` + xSID + `"}` + "\n"); err != nil {
		t.Fatal(err)
	}
}

func hasGen(t *testing.T, s *stack, key string, gen uint64) bool {
	t.Helper()
	gens, err := sweep.Generations(s.e, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gens {
		if g.Gen == gen {
			return true
		}
	}
	return false
}

// D85 (DATA-3): after a seal that left the main transcript behind
// (remove-failed), the next generation lacks the files the first seal
// deleted: it is partial, a restore brings them back from g1 and
// `prune --keep 1` keeps g1.
func TestPartialSealKeepsTheDeletedFilesInTheChain(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := filterSID(s.session(t, xSID, ""), xSID)
	orig := contents(t, paths)
	var main, sub string
	for _, p := range paths {
		switch {
		case filepath.Base(p) == xSID+".jsonl" && filepath.Base(filepath.Dir(filepath.Dir(p))) == "projects":
			main = p
		case filepath.Base(filepath.Dir(p)) == "subagents" && filepath.Ext(p) == ".jsonl":
			sub = p
		}
	}
	if main == "" || sub == "" {
		t.Fatalf("fixture: main=%q sub=%q", main, sub)
	}
	projDir := filepath.Dir(main)
	if err := os.Chmod(projDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(projDir, 0o700) })
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutRemoveFailed)
	if err != nil || res == nil {
		t.Fatalf("expected remove-failed: %+v %v", rep.Units, err)
	}
	key := res.Unit
	if err := os.Chmod(projDir, 0o700); err != nil {
		t.Fatal(err)
	}
	appendUserLine(t, main, "00000000-0000-4000-8000-00000000ffff")
	rep, err = sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	r2 := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if err != nil || r2 == nil || r2.Lineage != capsule.LineagePartial {
		t.Fatalf("second seal %+v %v", rep.Units, err)
	}
	ref := []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: key}}
	if _, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(sub); err != nil || string(got) != string(orig[sub]) {
		t.Fatalf("the subagent transcript (only in g1) was not restored: %v", err)
	}
	if _, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sweep.Prune(ctx, s.e, sweep.PruneOptions{Unit: key, KeepLast: 1}); err != nil {
		t.Fatal(err)
	}
	if !hasGen(t, s, key, 1) {
		t.Fatal("prune deleted g1, the only generation holding the subagent transcript")
	}
}

// D85: $TMP missing at restore (after a reboot) skips its entries; once
// Claude recreated $TMP and the session went on, the next generation is
// partial and the skipped files restore from g1 when $TMP is there.
func TestRestoreWithoutTmpKeepsTheTmpFilesInTheChain(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := filterSID(s.session(t, xSID, ""), xSID)
	orig := contents(t, paths)
	var main string
	var tmpFiles []string
	for _, p := range paths {
		if strings.HasPrefix(p, s.h.ClaudeTmp+string(filepath.Separator)) {
			tmpFiles = append(tmpFiles, p)
		}
		if filepath.Base(p) == xSID+".jsonl" && filepath.Base(filepath.Dir(filepath.Dir(p))) == "projects" {
			main = p
		}
	}
	if len(tmpFiles) == 0 || main == "" {
		t.Fatalf("fixture: tmp=%v main=%q", tmpFiles, main)
	}
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if err != nil || res == nil {
		t.Fatalf("seal %+v %v", rep.Units, err)
	}
	key := res.Unit
	ref := []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: key}}
	if err := os.RemoveAll(s.h.ClaudeTmp); err != nil {
		t.Fatal(err)
	}
	if _, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.h.ClaudeTmp, 0o700); err != nil {
		t.Fatal(err)
	}
	appendUserLine(t, main, "00000000-0000-4000-8000-00000000fffe")
	rep, err = sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	r2 := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if err != nil || r2 == nil || r2.Lineage != capsule.LineagePartial {
		t.Fatalf("second seal %+v %v", rep.Units, err)
	}
	if _, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref}); err != nil {
		t.Fatal(err)
	}
	for _, p := range tmpFiles {
		if got, err := os.ReadFile(p); err != nil || string(got) != string(orig[p]) {
			t.Fatalf("%s (only in g1) not restored: %v", filepath.Base(p), err)
		}
	}
	if _, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sweep.Prune(ctx, s.e, sweep.PruneOptions{Unit: key, KeepLast: 1}); err != nil {
		t.Fatal(err)
	}
	if !hasGen(t, s, key, 1) {
		t.Fatal("prune deleted g1, the only generation holding the $TMP files")
	}
}

// D86 (DATA-5): an ordinary Codex run (state and log databases rewritten
// in place, one the same size and one larger; a rollout appended) makes
// the exit seal a successor of the restored snapshot, and the next launch
// restores it byte for byte.
func TestCodexOrdinaryRunIsASuccessor(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	home := s.h.Layout.CodexHome(xRoot)
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	ch := codextest.New(t, home, codextest.Options{Rollouts: 2, Marker: testkit.Marker(t)})
	scan := func() []harness.Unit {
		units, err := codex.New().Scan(ctx, s.e.Harness, harness.Scope{RootIDs: []string{xRoot}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
		if err != nil || len(units) != 1 {
			t.Fatalf("scan %v %v", units, err)
		}
		return units
	}
	units := scan()
	if rep, err := sweep.Seal(ctx, s.e, units, sweep.Options{Reason: "codex-exit"}); err != nil || rep.Count(sweep.OutSealed) != 1 {
		t.Fatalf("seal 1 %+v %v", rep, err)
	}
	ref := units[0].Ref()
	want := map[string][]byte{}
	for cycle := 0; cycle < 2; cycle++ {
		if rep, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{ref}}); err != nil || rep.Count(sweep.OutRestored) != 1 {
			t.Fatalf("restore (cycle %d) %+v %v", cycle, rep, err)
		}
		for p, b := range want {
			if got, _ := os.ReadFile(p); string(got) != string(b) {
				t.Fatalf("cycle %d: %s is not what Codex wrote last", cycle, filepath.Base(p))
			}
		}
		state := filepath.Join(home, "state_5.sqlite")
		b, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-1] ^= 0xff // same size, rewritten in place
		if err := os.WriteFile(state, b, 0o600); err != nil {
			t.Fatal(err)
		}
		logs := filepath.Join(home, "logs_2.sqlite")
		lb, err := os.ReadFile(logs)
		if err != nil {
			t.Fatal(err)
		}
		lb[0] ^= 0x01
		lb = append(lb, make([]byte, 4096)...) // larger, not an append of the old bytes
		if err := os.WriteFile(logs, lb, 0o600); err != nil {
			t.Fatal(err)
		}
		ro := ch.Rollouts(t)[0]
		f, err := os.OpenFile(ro, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(`{"timestamp":"2026-11-21T10:00:00.000Z","type":"event_msg","payload":{"type":"agent_message","message":"x"}}` + "\n")
		f.Close()
		rb, _ := os.ReadFile(ro)
		want = map[string][]byte{state: b, logs: lb, ro: rb}
		rep, err := sweep.Seal(ctx, s.e, scan(), sweep.Options{Reason: "codex-exit"})
		if err != nil {
			t.Fatal(err)
		}
		r := resultOfKind(rep, capsule.KindCodexHome, sweep.OutSealed)
		if r == nil || r.Lineage != capsule.LineageSuccessor {
			t.Fatalf("exit seal (cycle %d) %+v", cycle, rep.Units)
		}
	}
	if rep, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{ref}}); err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("last restore %+v %v", rep, err)
	}
	for p, b := range want {
		if got, _ := os.ReadFile(p); string(got) != string(b) {
			t.Fatalf("%s is not what Codex wrote last", filepath.Base(p))
		}
	}
}

// genCopies lists the .precinto-g<k> copies in a directory.
func genCopies(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".precinto-g") {
			out = append(out, e.Name())
		}
	}
	return out
}

// D87 (DATA-6): files Claude rewrites in place after a restore (a task,
// a todo list, auto memory) are newer versions of what precinto placed:
// over three resume/lock cycles every re-seal is a successor, every
// restore is conflict-free and no .precinto-g copy appears.
func TestRewrittenSessionFilesSupersede(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := s.session(t, xSID, "")
	var main, task, todo, mem string
	for _, p := range paths {
		switch {
		case filepath.Base(p) == xSID+".jsonl" && filepath.Base(filepath.Dir(filepath.Dir(p))) == "projects":
			main = p
		case filepath.Base(filepath.Dir(p)) == xSID && filepath.Base(filepath.Dir(filepath.Dir(p))) == "tasks":
			task = p
		case filepath.Base(filepath.Dir(p)) == "todos" && strings.HasPrefix(filepath.Base(p), xSID):
			todo = p
		case filepath.Base(p) == "MEMORY.md":
			mem = p
		}
	}
	if main == "" || task == "" || todo == "" || mem == "" {
		t.Fatalf("fixture main=%q task=%q todo=%q mem=%q", main, task, todo, mem)
	}
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	sess := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	proj := resultOfKind(rep, capsule.KindClaudeProject, sweep.OutSealed)
	if err != nil || sess == nil || proj == nil {
		t.Fatalf("seal %+v %v", rep.Units, err)
	}
	refs := []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: sess.Unit},
		{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeProject, Key: proj.Unit}}
	for cycle := 1; cycle <= 3; cycle++ {
		rep, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: refs})
		if err != nil || rep.Count(sweep.OutRestored) != 2 {
			t.Fatalf("restore %d %+v %v", cycle, rep.Units, err)
		}
		n := string(rune('0' + cycle))
		old := s.clock.Now().Add(-time.Hour)
		for p, body := range map[string]string{
			task: `{"id":"1","subject":"t","status":"completed","cycle":` + n + `}`,
			todo: `[{"content":"t","status":"completed","cycle":` + n + `}]`,
			mem:  "# memory\n\n- fact revised in cycle " + n + "\n",
		} {
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(p, old, old)
		}
		appendUserLine(t, main, "00000000-0000-4000-8000-0000000000"+string(rune('a'+cycle))+"0")
		_ = os.Chtimes(main, old, old)
		rep, err = sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []capsule.Kind{capsule.KindClaudeSession, capsule.KindClaudeProject} {
			if r := resultOfKind(rep, k, sweep.OutSealed); r == nil || r.Lineage != capsule.LineageSuccessor {
				t.Fatalf("cycle %d: %s re-seal %+v", cycle, k, rep.Units)
			}
		}
	}
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: refs})
	if err != nil || rep.Count(sweep.OutRestored) != 2 || rep.Count(sweep.OutConflict) != 0 {
		t.Fatalf("final restore %+v %v", rep.Units, err)
	}
	for _, dir := range []string{filepath.Dir(task), filepath.Dir(todo), filepath.Dir(mem)} {
		if c := genCopies(t, dir); len(c) != 0 {
			t.Fatalf("stale generation copies in %s: %v", filepath.Base(dir), c)
		}
	}
	if b, _ := os.ReadFile(mem); !strings.Contains(string(b), "cycle 3") {
		t.Fatal("the newest memory is not at its path")
	}
}

// D88 (DATA-8): `resolve --keep capsule` on a session file survives the
// next lock and unlock: the capsule side stays at the path, the restore
// reports no conflict and leaves no copy, and the rejected side is still
// a logged (diverged) generation.
func TestResolveKeepCapsuleKeepsTheChoice(t *testing.T) {
	s := newStack(t)
	ctx := testCtx(t)
	paths := filterSID(s.session(t, xSID, ""), xSID)
	var tr string
	for _, p := range paths {
		if filepath.Base(filepath.Dir(p)) == "tool-results" {
			tr = p
		}
	}
	if tr == "" {
		t.Fatal("fixture: no tool result")
	}
	capsuleSide, _ := os.ReadFile(tr)
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if err != nil || res == nil {
		t.Fatalf("seal %+v %v", rep.Units, err)
	}
	ref := []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: res.Unit}}
	if err := os.MkdirAll(filepath.Dir(tr), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tr, []byte("a different version written while the session was sealed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref}); err != nil || rep.Count(sweep.OutConflict) != 1 {
		t.Fatalf("restore 1 %+v %v", rep, err)
	}
	if rep, err := sweep.Resolve(ctx, s.e, s.keys, tr, "capsule"); err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("resolve %+v %v", rep, err)
	}
	if _, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true}); err != nil {
		t.Fatal(err)
	}
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: ref})
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore 2 %+v %v", rep.Units, err)
	}
	if got, _ := os.ReadFile(tr); string(got) != string(capsuleSide) {
		t.Fatal("the rejected side is back at the path")
	}
	if c := genCopies(t, filepath.Dir(tr)); len(c) != 0 {
		t.Fatalf("copies: %v", c)
	}
	gens, err := sweep.Generations(s.e, res.Unit)
	if err != nil {
		t.Fatal(err)
	}
	diverged := false
	for _, g := range gens {
		if g.Lineage == capsule.LineageDiverged {
			diverged = true
		}
	}
	if !diverged {
		t.Fatalf("the rejected side is not a logged generation: %+v", gens)
	}
}
