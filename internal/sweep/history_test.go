package sweep

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
)

func (te *testEnv) historyPath() string { return filepath.Join(te.h.ClaudeConfig, historyRel) }

func (te *testEnv) historyKey() string {
	k, err := harness.UnitKeyFor(te.e.Harness.Salt, capsule.KindClaudeHistory, harness.ClaudeCode, te.cc.ID, rootID, "")
	mustNoErr(te.t, err)
	return k
}

// historyLines returns the lines of history.jsonl.
func (te *testEnv) historyLines() []string {
	b, err := os.ReadFile(te.historyPath())
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range splitLines(b) {
		out = append(out, string(l))
	}
	return out
}

// sealedHistory decrypts every history generation of the root (fake
// codec) and returns their lines.
func (te *testEnv) sealedHistory() []string {
	te.t.Helper()
	var out []string
	for _, en := range te.logged(te.historyKey()) {
		b := readFile(te.t, filepath.Join(te.h.Layout.CapsulesDir, filepath.FromSlash(en.Path)))
		h, body, err := splitFake(b)
		mustNoErr(te.t, err)
		_ = h
		var fb fakeBody
		mustNoErr(te.t, json.Unmarshal(body, &fb))
		for i, f := range fb.Manifest.Files {
			if f.Rel == historyRel {
				var data []byte
				data, _ = decodeB64(fb.Data[i])
				for _, l := range splitLines(data) {
					out = append(out, string(l))
				}
			}
		}
	}
	return out
}

// historyLineFor renders one history.jsonl line (claudetest's shape).
func historyLineFor(project, text string, ts int64, paste string) string {
	m := map[string]any{"display": text, "pastedContents": map[string]any{}, "timestamp": ts, "project": project}
	if paste != "" {
		m["pastedContents"] = map[string]any{"1": map[string]any{"id": 1, "type": "text", "contentHash": paste}}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func appendLines(t *testing.T, p string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	mustNoErr(t, err)
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	mustNoErr(t, f.Close())
}

func TestRotateHistoryMovesRootLinesAndTheirPastes(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	l := claudetest.New(t, te.h.Dir)
	outside := filepath.Join(te.h.HomeDir, "elsewhere")
	mrk := testkit.Marker(t)
	l.WriteHistory(t, te.h.Root, sid1, 4, mrk)
	l.WriteHistory(t, outside, sid2, 3, mrk+"x")
	all := te.historyLines()
	var kept, extracted []string
	for _, ln := range all {
		if testHistoryLine([]byte(ln)).Project == te.h.Root {
			extracted = append(extracted, ln)
		} else {
			kept = append(kept, ln)
		}
	}
	pastes, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, "paste-cache", "*"))
	r := te.run()
	r.rotateHistory(context.Background())
	rep := r.finish()
	if rep.Count(OutSealed) != 1 {
		t.Fatalf("rotation %+v", rep.Units)
	}
	if got := te.historyLines(); fmt.Sprint(got) != fmt.Sprint(kept) {
		t.Fatalf("kept lines changed:\n%v\nwant\n%v", got, kept)
	}
	if got := te.sealedHistory(); fmt.Sprint(got) != fmt.Sprint(extracted) {
		t.Fatalf("sealed lines %v, want %v", got, extracted)
	}
	// Paste-cache entries referenced only by extracted lines moved.
	left, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, "paste-cache", "*"))
	if len(left) >= len(pastes) || len(left) == 0 {
		t.Fatalf("paste cache %d → %d", len(pastes), len(left))
	}
	for _, p := range left {
		if bytes.Contains(readFile(t, p), []byte(mrk+" ")) {
			t.Fatalf("a root paste stayed: %s", filepath.Base(p))
		}
	}
	if holds, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, ".precinto-hold-*")); len(holds) != 0 {
		t.Fatalf("hold left: %v", holds)
	}
	if hits := testkit.GrepTree(t, te.h.Base, mrk, "capsules"); len(hits) != 0 {
		t.Fatalf("history content leaked into precinto metadata: %v", hits)
	}
	// Merge-back restores the lines and pastes; a second merge adds
	// nothing (HIST-5).
	mr := te.run()
	mr.mergeHistory(context.Background(), te.keys, rootID)
	if res := outcome(t, mr.finish(), te.historyKey()); res.Outcome != OutMerged || res.Files != len(extracted) {
		t.Fatalf("merge %+v", res)
	}
	got := te.historyLines()
	if len(got) != len(all) {
		t.Fatalf("after merge %d lines, want %d", len(got), len(all))
	}
	sort.Strings(got)
	want := append([]string(nil), all...)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatal("merged lines differ from the originals")
	}
	back, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, "paste-cache", "*"))
	if len(back) != len(pastes) {
		t.Fatalf("pastes after merge %d, want %d", len(back), len(pastes))
	}
	mr2 := te.run()
	mr2.mergeHistory(context.Background(), te.keys, rootID)
	if res := outcome(t, mr2.finish(), te.historyKey()); res.Outcome != OutUnchanged {
		t.Fatalf("second merge %+v", res)
	}
	if len(te.historyLines()) != len(all) {
		t.Fatal("HIST-5: the second merge appended duplicates")
	}
}

func TestRotateHistoryWaitsWhileClaudeRuns(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	appendLines(t, te.historyPath(), historyLineFor(te.h.Root, "p", 1, ""))
	before, _ := fsx.Lstat(te.historyPath())
	jkey, _ := te.run().historyJournalKey(te.cc)
	te.claude.probe[jkey] = []live.Evidence{{Reason: live.ReasonProcess}}
	r := te.run()
	r.rotateHistory(context.Background())
	if res := outcome(t, r.finish(), jkey); res.Outcome != OutLive {
		t.Fatalf("result %+v", res)
	}
	if after, _ := fsx.Lstat(te.historyPath()); !after.Unchanged(before) {
		t.Fatal("history rewritten while Claude runs (D21)")
	}
}

func TestRotateHistoryLeavesUnprotectedHistoryAlone(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	appendLines(t, te.historyPath(), historyLineFor("/somewhere/else", "p", 1, ""), "not json")
	before, _ := fsx.Lstat(te.historyPath())
	r := te.run()
	r.rotateHistory(context.Background())
	if len(r.finish().Units) != 0 {
		t.Fatal("rotation reported work")
	}
	if after, _ := fsx.Lstat(te.historyPath()); !after.Unchanged(before) {
		t.Fatal("history rewritten without protected lines")
	}
}

// The deepest root wins (D36).
func TestRotateHistoryUsesTheDeepestRoot(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	inner := te.h.Protect(t, "work/acme/inner")
	te.e.Cfg = te.h.Cfg
	te.e.Harness.Cfg = te.h.Cfg
	appendLines(t, te.historyPath(), historyLineFor(filepath.Join(te.h.Root, "inner", "x"), "deep", 1, ""), historyLineFor(te.h.Root, "top", 2, ""))
	r := te.run()
	r.rotateHistory(context.Background())
	r.finish()
	innerKey, _ := harness.UnitKeyFor(te.e.Harness.Salt, capsule.KindClaudeHistory, harness.ClaudeCode, te.cc.ID, inner.ID, "")
	if len(te.logged(innerKey)) != 1 || len(te.logged(te.historyKey())) != 1 {
		t.Fatalf("inner %d, outer %d generations", len(te.logged(innerKey)), len(te.logged(te.historyKey())))
	}
	if en := te.logged(innerKey)[0]; en.VaultID != inner.ID {
		t.Fatalf("inner lines sealed to vault %s", en.VaultID)
	}
}

// HIST-1: concurrent appends during the extract: every line ends up
// exactly once, in the new file or in a history generation.
func TestRotateHistoryUnderConcurrentAppends(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	var seed []string
	for i := 0; i < 10; i++ {
		seed = append(seed, historyLineFor(te.h.Root, "seed "+itoa(i), int64(i), ""), historyLineFor("/elsewhere", "other "+itoa(i), int64(i), ""))
	}
	appendLines(t, te.historyPath(), seed...)
	// A writer that opened the file before the rename keeps appending
	// through its descriptor (the hold inode).
	held, err := os.OpenFile(te.historyPath(), os.O_WRONLY|os.O_APPEND, 0)
	mustNoErr(t, err)
	defer held.Close()
	var mu sync.Mutex
	var written []string
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				select {
				case <-stop:
					return
				default:
				}
				project := te.h.Root
				if i%2 == 1 {
					project = "/elsewhere"
				}
				ln := historyLineFor(project, fmt.Sprintf("w%d-%d", w, i), int64(100+w*10+i), "")
				mu.Lock()
				if w == 0 {
					_, _ = held.WriteString(ln + "\n")
				} else {
					appendLines(t, te.historyPath(), ln)
				}
				written = append(written, ln)
				mu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}(w)
	}
	te.p.tailQuiet = 30 * time.Millisecond
	te.p.sleep = func(ctx context.Context, d time.Duration) error { time.Sleep(d); return nil }
	r := te.run()
	r.rotateHistory(context.Background())
	wg.Wait()
	close(stop)
	// Lines that landed in the new file after the rename are extracted by
	// the next rotation.
	r2 := te.run()
	r2.rotateHistory(context.Background())
	all := append(append([]string(nil), seed...), written...)
	inFile := map[string]int{}
	for _, l := range te.historyLines() {
		inFile[l]++
	}
	sealed := map[string]int{}
	for _, l := range te.sealedHistory() {
		sealed[l]++
	}
	for _, l := range all {
		root := testHistoryLine([]byte(l)).Project == te.h.Root
		if n := inFile[l] + sealed[l]; n != 1 {
			t.Errorf("line %s found %d times (file %d, sealed %d)", l, n, inFile[l], sealed[l])
		}
		if root && inFile[l] != 0 {
			t.Errorf("protected line still in history.jsonl: %s", l)
		}
	}
}

// HIST-6: merge-back while an appender writes loses nothing.
func TestMergeHistoryWhileAppending(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	var mine []string
	for i := 0; i < 5; i++ {
		mine = append(mine, historyLineFor(te.h.Root, "m"+itoa(i), int64(i), ""))
	}
	appendLines(t, te.historyPath(), mine...)
	r := te.run()
	r.rotateHistory(context.Background())
	r.finish()
	var wg sync.WaitGroup
	var theirs []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			ln := historyLineFor("/elsewhere", "live "+itoa(i), int64(1000+i), "")
			appendLines(t, te.historyPath(), ln)
			theirs = append(theirs, ln)
		}
	}()
	mr := te.run()
	mr.mergeHistory(context.Background(), te.keys, rootID)
	wg.Wait()
	got := map[string]int{}
	for _, l := range te.historyLines() {
		got[l]++
	}
	for _, l := range append(mine, theirs...) {
		if got[l] != 1 {
			t.Fatalf("line %s present %d times", l, got[l])
		}
	}
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// historyEntries is a test helper listing the log entries of a key.
func historyEntries(t *testing.T, l *capslog.Log, key string) []capslog.Entry {
	t.Helper()
	en, err := l.Unit(key)
	mustNoErr(t, err)
	return en
}

// SPEC §7.1.1: stale shell snapshots (older than a day, not open) are
// deleted by sweeps while no Claude process runs; never sealed.
func TestShellSnapshotsArePruned(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	dir := filepath.Join(te.h.ClaudeConfig, "shell-snapshots")
	mk := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		writeAt(t, p, []byte("export X=1\n"))
		at := te.h.Clock.Now().Add(-age)
		mustNoErr(t, os.Chtimes(p, at, at))
		return p
	}
	old := mk("snapshot-zsh-1.sh", 48*time.Hour)
	fresh := mk("snapshot-zsh-2.sh", time.Hour)
	held := mk("snapshot-zsh-3.sh", 48*time.Hour)
	other := mk("notes.txt", 48*time.Hour)
	hard := mk("snapshot-zsh-4.sh", 48*time.Hour)
	mustNoErr(t, os.Link(hard, filepath.Join(te.h.HomeDir, "hard-link")))
	mustNoErr(t, os.Chtimes(hard, te.h.Clock.Now().Add(-48*time.Hour), te.h.Clock.Now().Add(-48*time.Hour)))
	te.h.Procs.Add(procInfo(777, 1))
	te.h.Procs.SetOpenFiles(777, held)
	// While Claude runs nothing is touched.
	jkey, _ := te.run().historyJournalKey(te.cc)
	te.claude.probe[jkey] = []live.Evidence{{Reason: live.ReasonProcess}}
	te.run().rotateHistory(context.Background())
	if !exists(old) {
		t.Fatal("pruned while Claude runs")
	}
	delete(te.claude.probe, jkey)
	te.run().rotateHistory(context.Background())
	if exists(old) {
		t.Fatal("stale snapshot kept")
	}
	for _, p := range []string{fresh, held, other, hard} {
		if !exists(p) {
			t.Errorf("%s deleted", filepath.Base(p))
		}
	}
	if len(te.allLogged()) != 0 {
		t.Fatal("shell snapshots were sealed")
	}
}

// Retention never prunes history generations: each holds other lines.
func TestPruneKeepsEveryHistoryGeneration(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	for i := 0; i < 5; i++ {
		appendLines(t, te.historyPath(), historyLineFor(te.h.Root, "r"+itoa(i), int64(i), ""))
		r := te.run()
		r.rotateHistory(context.Background())
		r.finish()
	}
	if n := len(te.logged(te.historyKey())); n != 5 {
		t.Fatalf("%d history generations", n)
	}
	te.run().prune(context.Background(), PruneOptions{KeepLast: 1, Diverged: true})
	if n := len(te.logged(te.historyKey())); n != 5 {
		t.Fatalf("prune deleted history: %d left", n)
	}
	if got := te.sealedHistory(); len(got) != 5 {
		t.Fatalf("sealed lines %d", len(got))
	}
}
