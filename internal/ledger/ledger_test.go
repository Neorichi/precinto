package ledger_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ledger"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/testkit"
)

const (
	hcc  = "claude-code"
	sidA = "00000000-0000-4000-8000-00000000000a"
	sidB = "00000000-0000-4000-8000-00000000000b"
)

var (
	t0    = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	procP = platform.ProcID{PID: 4242, StartUS: 1_700_000_000_000_000}
	procQ = platform.ProcID{PID: 4343, StartUS: 1_700_000_000_500_000}
)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func newLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	return ledger.Open(filepath.Join(t.TempDir(), "state", "sessions"))
}

func appendAll(t *testing.T, l *ledger.Ledger, events ...ledger.Event) {
	t.Helper()
	for _, e := range events {
		if e.Harness == "" {
			e.Harness = hcc
		}
		if err := l.Append(e); err != nil {
			t.Fatalf("Append(%s): %v", e.Type, err)
		}
	}
}

func TestAppendCreatesThePrivateSessionFile(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	if _, err := l.Get(hcc, sidA); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("Get before any event: %v, want ErrNotFound", err)
	}
	appendAll(t, l, ledger.Event{Type: ledger.TypeStart, SID: sidA, Proc: procP, Cwd: "/u/work/acme", Roots: []string{"root-acme"}})
	path := filepath.Join(l.Dir, hcc, sidA+".jsonl")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ledger file mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("ledger dir mode %v (%v), want 0700", di.Mode().Perm(), err)
	}
	var e ledger.Event
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(bytes.TrimSpace(raw), &e); err != nil {
		t.Fatal(err)
	}
	if e.V != ledger.Version || e.T.IsZero() {
		t.Errorf("V/T not filled: %+v", e)
	}
}

func TestAppendRejectsBadEvents(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	for name, e := range map[string]ledger.Event{
		"no type":          {Harness: hcc, SID: sidA},
		"no sid":           {Harness: hcc, Type: ledger.TypeStart},
		"sid with slash":   {Harness: hcc, SID: "../x", Type: ledger.TypeStart},
		"dot sid":          {Harness: hcc, SID: "..", Type: ledger.TypeStart},
		"no harness":       {SID: sidA, Type: ledger.TypeStart},
		"relative cwd":     {Harness: hcc, SID: sidA, Type: ledger.TypeCwd, Cwd: "work/acme"},
		"relative md path": {Harness: hcc, SID: sidA, Type: ledger.TypeMarkdown, Path: "notes.md"},
		"control char sid": {Harness: hcc, SID: "a\nb", Type: ledger.TypeStart},
		"empty root id":    {Harness: hcc, SID: sidA, Type: ledger.TypeTaint, Roots: []string{""}},
		"reserved type":    {Harness: hcc, SID: sidA, Type: "archived"},
	} {
		if err := l.Append(e); err == nil {
			t.Errorf("%s: Append accepted it", name)
		}
	}
	if err := ledger.Open("relative/dir").Append(ledger.Event{Harness: hcc, SID: sidA, Type: ledger.TypeStart}); err == nil {
		t.Error("a relative ledger directory was accepted")
	}
	var nilLedger *ledger.Ledger
	if err := nilLedger.Append(ledger.Event{Harness: hcc, SID: sidA, Type: ledger.TypeStart}); err == nil {
		t.Error("a nil ledger accepted an event")
	}
}

func TestFoldRules(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l,
		ledger.Event{T: at(0), Type: ledger.TypeLaunch, SID: sidA, Proc: procP, Wrapper: true, ConfigDir: "/u/cc", LeaseKey: "k"},
		ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP, Source: "startup", Cwd: "/u/work/acme",
			ProjectDir: "/u/work/acme", Roots: []string{"root-acme"}, Transcript: "/u/cc/projects/p/a.jsonl",
			HarnessVersion: "2.1.329", Entrypoint: "cli", TmpDir: "/tmp/claude-501"},
		ledger.Event{T: at(2), Type: ledger.TypeCwd, SID: sidA, Cwd: "/u/work/acme/sub"},
		ledger.Event{T: at(3), Type: ledger.TypeDir, SID: sidA, Path: "/u/work/other", Roots: []string{"root-other"}},
		ledger.Event{T: at(4), Type: ledger.TypeMarkdown, SID: sidA, Path: "/u/work/acme/docs/a.md"},
		ledger.Event{T: at(5), Type: ledger.TypeMarkdown, SID: sidA, Path: "/u/work/acme/docs/a.md"},
		ledger.Event{T: at(6), Type: ledger.TypeCompactBegin, SID: sidA},
		ledger.Event{T: at(7), Type: "future-event-type", SID: sidA, Roots: []string{"root-late"}},
		ledger.Event{T: at(8), Type: ledger.TypeTaint, SID: sidA, Roots: []string{"root-acme"}},
	)
	s, err := l.Get(hcc, sidA)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Managed() || !reflect.DeepEqual(s.RootIDs, []string{"root-acme", "root-other", "root-late"}) {
		t.Errorf("RootIDs = %v (sticky union, first = primary)", s.RootIDs)
	}
	if s.CurrentProc != procP || !reflect.DeepEqual(s.Procs, []platform.ProcID{procP}) {
		t.Errorf("procs = %v current %v", s.Procs, s.CurrentProc)
	}
	if !reflect.DeepEqual(s.Cwds, []string{"/u/work/acme", "/u/work/acme/sub"}) || !reflect.DeepEqual(s.Dirs, []string{"/u/work/other"}) {
		t.Errorf("cwds %v dirs %v", s.Cwds, s.Dirs)
	}
	if !reflect.DeepEqual(s.Markdown, []string{"/u/work/acme/docs/a.md"}) {
		t.Errorf("markdown %v", s.Markdown)
	}
	if !s.Compacting || !s.CompactAt.Equal(at(6)) {
		t.Errorf("compacting %v at %v", s.Compacting, s.CompactAt)
	}
	if !s.Wrapper || !s.HooksSeen || s.Version != "2.1.329" || s.Entrypoint != "cli" || s.Ended || s.Warm() {
		t.Errorf("flags: %+v", s)
	}
	if !s.Started.Equal(at(0)) || !s.LastEvent.Equal(at(8)) {
		t.Errorf("started %v last %v", s.Started, s.LastEvent)
	}
	if !reflect.DeepEqual(s.ConfigDirs, []string{"/u/cc"}) || !reflect.DeepEqual(s.TmpDirs, []string{"/tmp/claude-501"}) {
		t.Errorf("homes %v %v", s.ConfigDirs, s.TmpDirs)
	}

	// SessionEnd's transcript is trusted over SessionStart's; end clears
	// compaction; the end record does not make the process dead (R8).
	appendAll(t, l, ledger.Event{T: at(9), Type: ledger.TypeEnd, SID: sidA, Proc: procP, Reason: "other", Transcript: "/u/cc/projects/q/a.jsonl"})
	s, _ = l.Get(hcc, sidA)
	if !s.Ended || s.EndReason != "other" || s.EndProc != procP || s.Compacting || s.Warm() {
		t.Errorf("after end: %+v", s)
	}
	if s.Transcript != "/u/cc/projects/q/a.jsonl" {
		t.Errorf("transcript %q, want SessionEnd's", s.Transcript)
	}
	if s.CurrentProc != procP {
		t.Errorf("end changed the current process")
	}
	// A resume of the same session id in a new process starts it again.
	appendAll(t, l, ledger.Event{T: at(10), Type: ledger.TypeStart, SID: sidA, Proc: procQ, Source: "resume"})
	s, _ = l.Get(hcc, sidA)
	if s.Ended || s.EndReason != "" || s.CurrentProc != procQ || !reflect.DeepEqual(s.Procs, []platform.ProcID{procP, procQ}) {
		t.Errorf("after resume: ended %v reason %q current %v procs %v", s.Ended, s.EndReason, s.CurrentProc, s.Procs)
	}
}

func TestCompactionClearedByStopEndAndCompactStart(t *testing.T) {
	t.Parallel()
	for name, clear := range map[string]ledger.Event{
		"compact_end (PostCompact/Stop/StopFailure)": {Type: ledger.TypeCompactEnd},
		"SessionStart(compact)":                      {Type: ledger.TypeStart, Source: "compact", Proc: procP},
		"end":                                        {Type: ledger.TypeEnd, Reason: "other"},
	} {
		l := newLedger(t)
		clear.SID, clear.T = sidA, at(3)
		appendAll(t, l,
			ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP},
			ledger.Event{T: at(2), Type: ledger.TypeCompactBegin, SID: sidA},
			clear)
		s, err := l.Get(hcc, sidA)
		if err != nil {
			t.Fatal(err)
		}
		if s.Compacting {
			t.Errorf("%s did not clear compaction", name)
		}
	}
}

func TestWarmAfterClearOrResume(t *testing.T) {
	t.Parallel()
	for reason, warm := range map[string]bool{"clear": true, "resume": true, "logout": false, "prompt_input_exit": false, "other": false} {
		l := newLedger(t)
		appendAll(t, l,
			ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP},
			ledger.Event{T: at(2), Type: ledger.TypeEnd, SID: sidA, Proc: procP, Reason: reason})
		s, _ := l.Get(hcc, sidA)
		if s.Warm() != warm {
			t.Errorf("reason %s: Warm = %v, want %v", reason, s.Warm(), warm)
		}
	}
}

// D20: after /clear the process owns only its newer session.
func TestByProcAfterClear(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l,
		ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP, Roots: []string{"root-acme"}},
		ledger.Event{T: at(5), Type: ledger.TypeEnd, SID: sidA, Proc: procP, Reason: "clear"},
		ledger.Event{T: at(6), Type: ledger.TypeStart, SID: sidB, Proc: procP, Source: "clear", Roots: []string{"root-acme"}},
	)
	got, err := l.ByProc(hcc, procP)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SID != sidB {
		t.Fatalf("ByProc = %+v, want only the newer session", got)
	}
	if got, _ := l.ByProc(hcc, procQ); len(got) != 0 {
		t.Fatalf("ByProc(other process) = %+v", got)
	}
	if got, _ := l.ByProc(hcc, platform.ProcID{}); got != nil {
		t.Fatalf("ByProc(zero) = %+v", got)
	}
	// Same pid, other start time: another process (PID reuse).
	reused := platform.ProcID{PID: procP.PID, StartUS: procP.StartUS + 1}
	if got, _ := l.ByProc(hcc, reused); len(got) != 0 {
		t.Fatalf("ByProc(reused pid) = %+v", got)
	}
	all, err := l.List(hcc)
	if err != nil || len(all) != 2 || all[0].SID != sidA || all[1].SID != sidB {
		t.Fatalf("List = %+v, %v", all, err)
	}
	if !all[0].Warm() || all[1].Warm() {
		t.Errorf("warm flags: %v %v", all[0].Warm(), all[1].Warm())
	}
}

// SPEC §14.3: the first managed contact of a session without a ledger is a
// start event with an empty source. It is the session's start (process,
// homes, transcript) when it opens the ledger, and only facts when the
// session already started: a session that ended with /clear stays ended and
// warm, and the process keeps owning its newer session (D20).
func TestFoldFirstContactStart(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	// A session that became managed after its SessionStart (a tool touched
	// the folder): its first event is the first-contact start.
	appendAll(t, l,
		ledger.Event{T: at(2), Type: ledger.TypeStart, SID: sidA, Proc: procP, Cwd: "/u/other", ConfigDir: "/u/cc",
			TmpDir: "/tmp/claude-501", Transcript: "/u/cc/projects/p/a.jsonl"},
		ledger.Event{T: at(2), Type: ledger.TypeTaint, SID: sidA, Roots: []string{"root-acme"}},
		ledger.Event{T: at(2), Type: ledger.TypeTouch, SID: sidA, Path: "/u/work/acme/x.go"},
	)
	s, err := l.Get(hcc, sidA)
	if err != nil {
		t.Fatal(err)
	}
	if s.CurrentProc != procP || !reflect.DeepEqual(s.Procs, []platform.ProcID{procP}) || !s.Started.Equal(at(2)) || s.Ended {
		t.Errorf("first contact: current %v procs %v started %v ended %v", s.CurrentProc, s.Procs, s.Started, s.Ended)
	}
	if !reflect.DeepEqual(s.ConfigDirs, []string{"/u/cc"}) || !reflect.DeepEqual(s.TmpDirs, []string{"/tmp/claude-501"}) ||
		s.Transcript != "/u/cc/projects/p/a.jsonl" || !s.Managed() || !s.HooksSeen {
		t.Errorf("first-contact facts: %+v", s)
	}
	if got, _ := l.ByProc(hcc, procP); len(got) != 1 || got[0].SID != sidA {
		t.Fatalf("ByProc after the first contact = %+v", got)
	}

	// /clear: the old session ends, the new one starts in the same
	// process and becomes managed at its own first contact.
	appendAll(t, l,
		ledger.Event{T: at(5), Type: ledger.TypeEnd, SID: sidA, Proc: procP, Reason: "clear"},
		ledger.Event{T: at(7), Type: ledger.TypeStart, SID: sidB, Proc: procP, Cwd: "/u/other"},
	)
	if got, _ := l.ByProc(hcc, procP); len(got) != 1 || got[0].SID != sidB {
		t.Fatalf("ByProc after /clear = %+v, want only the newer session", got)
	}
	// A stray first-contact start of the cleared session (a hook that found
	// no ledger while an Archive replaced it) is not a new session.
	appendAll(t, l, ledger.Event{T: at(9), Type: ledger.TypeStart, SID: sidA, Proc: procP, Cwd: "/u/other", ConfigDir: "/u/cc2"})
	s, _ = l.Get(hcc, sidA)
	if !s.Ended || s.EndReason != "clear" || !s.Warm() || s.CurrentProc != procP {
		t.Errorf("after a stray first contact: ended %v reason %q warm %v current %v", s.Ended, s.EndReason, s.Warm(), s.CurrentProc)
	}
	if !reflect.DeepEqual(s.ConfigDirs, []string{"/u/cc", "/u/cc2"}) {
		t.Errorf("a stray first contact still records its facts: %v", s.ConfigDirs)
	}
	if got, _ := l.ByProc(hcc, procP); len(got) != 1 || got[0].SID != sidB {
		t.Fatalf("ByProc after a stray first contact = %+v, want the newer session", got)
	}
	// A real SessionStart (resume) of the cleared session does restart it.
	appendAll(t, l, ledger.Event{T: at(11), Type: ledger.TypeStart, SID: sidA, Proc: procQ, Source: "resume"})
	s, _ = l.Get(hcc, sidA)
	if s.Ended || s.Warm() || s.CurrentProc != procQ {
		t.Errorf("after resume: ended %v warm %v current %v", s.Ended, s.Warm(), s.CurrentProc)
	}
}

func TestListSkipsForeignAndBrokenEntries(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l, ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP})
	dir := filepath.Join(l.Dir, hcc)
	// A torn last line (no newline), a line of another session, garbage.
	path := filepath.Join(dir, sidA+".jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(ledger.Event{V: 1, T: at(2), Type: ledger.TypeTaint, Harness: hcc, SID: sidB, Roots: []string{"root-x"}})
	f.Write(append(other, '\n'))
	f.Write([]byte("not json\n"))
	f.Write([]byte(`{"v":1,"type":"taint","harness":"claude-code","sid":"` + sidA + `","roots":["root-torn"]`))
	f.Close()
	if err := os.Symlink(path, filepath.Join(dir, sidB+".jsonl")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600)
	all, err := l.List(hcc)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].SID != sidA || len(all[0].RootIDs) != 0 {
		t.Fatalf("List = %+v", all)
	}
	if _, err := l.Get(hcc, sidB); err == nil {
		t.Fatal("Get followed a symlinked ledger file")
	}
	if got, err := l.List("codex"); err != nil || got != nil {
		t.Fatalf("List of a harness without ledgers = %v, %v", got, err)
	}
}

// SEAL-15 (G3 part): events a hook appends between Snapshot and Archive
// stay in the ledger and go into the next generation.
func TestSnapshotArchiveKeepsLaterEvents(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l,
		ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP, Roots: []string{"root-acme"}},
		ledger.Event{T: at(2), Type: ledger.TypeMarkdown, SID: sidA, Path: "/u/work/acme/a.md"},
	)
	raw, n, err := l.Snapshot(hcc, sidA)
	if err != nil || int64(len(raw)) != n || n == 0 {
		t.Fatalf("Snapshot = %d bytes, n %d, %v", len(raw), n, err)
	}
	appendAll(t, l, ledger.Event{T: at(3), Type: ledger.TypeEnd, SID: sidA, Proc: procP, Reason: "other"})
	if err := l.Archive(hcc, sidA, n); err != nil {
		t.Fatal(err)
	}
	s, err := l.Get(hcc, sidA)
	if err != nil {
		t.Fatalf("the later event was lost: %v", err)
	}
	if !s.Ended || s.EndReason != "other" || len(s.Markdown) != 0 || s.Managed() {
		t.Fatalf("kept ledger = %+v, want only the end event", s)
	}
	// A repeated Archive of the same snapshot (journal recovery) is a
	// no-op: it must not cut the kept events.
	if err := l.Archive(hcc, sidA, n); err != nil {
		t.Fatal(err)
	}
	if s2, err := l.Get(hcc, sidA); err != nil || !s2.Ended {
		t.Fatalf("repeated Archive cut the kept events: %+v %v", s2, err)
	}
	// The next generation archives the rest: the file goes away.
	raw2, n2, err := l.Snapshot(hcc, sidA)
	if err != nil || !bytes.Contains(raw2, []byte(`"type":"end"`)) {
		t.Fatalf("second snapshot: %v", err)
	}
	if err := l.Archive(hcc, sidA, n2); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(hcc, sidA); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("after the final Archive Get = %v, want ErrNotFound", err)
	}
	// Archive of a missing ledger is a no-op.
	if err := l.Archive(hcc, sidA, n2); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveRemovesAndRecoveryNeverCutsANewLedger(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l, ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP, Roots: []string{"root-acme"}})
	_, n, err := l.Snapshot(hcc, sidA)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Archive(hcc, sidA, n); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(l.Dir, hcc, sidA+".jsonl")); !os.IsNotExist(err) {
		t.Fatalf("the ledger file was not removed: %v", err)
	}
	// The session is resumed: hooks write a new ledger of the same length.
	appendAll(t, l, ledger.Event{T: at(1), Type: ledger.TypeStart, SID: sidA, Proc: procP, Roots: []string{"root-acme"}})
	if _, n3, _ := l.Snapshot(hcc, sidA); n3 != n {
		t.Fatalf("fixture: lengths differ (%d vs %d)", n3, n)
	}
	// Journal recovery repeats the old Archive: the new ledger survives.
	if err := l.Archive(hcc, sidA, n); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(hcc, sidA); err != nil {
		t.Fatalf("a repeated Archive removed a newer ledger: %v", err)
	}
	// A ledger shorter than the snapshot is never cut.
	if err := l.Archive(hcc, sidA, n+1000); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(hcc, sidA); err != nil {
		t.Fatalf("Archive cut a shorter ledger: %v", err)
	}
	if err := l.Archive(hcc, sidA, -1); err == nil {
		t.Fatal("negative length accepted")
	}
	// The tombstone log holds no session id.
	tomb, err := os.ReadFile(filepath.Join(l.Dir, hcc, ".archived"))
	if err != nil || bytes.Contains(tomb, []byte(sidA)) {
		t.Fatalf("tombstones: %q, %v", tomb, err)
	}
}

func TestArchiveUnderConcurrentAppends(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	appendAll(t, l, ledger.Event{T: at(0), Type: ledger.TypeStart, SID: sidA, Proc: procP})
	for round := 0; round < 5; round++ {
		_, n, err := l.Snapshot(hcc, sidA)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		const writers, each = 4, 25
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; i < each; i++ {
					p := filepath.Join("/u/work/acme", "w", string(rune('a'+w)), strings.Repeat("x", i%3), "n.md")
					if err := l.Append(ledger.Event{Harness: hcc, SID: sidA, Type: ledger.TypeMarkdown, Path: p, T: at(round*1000 + w*100 + i + 1)}); err != nil {
						t.Error(err)
					}
				}
			}(w)
		}
		if err := l.Archive(hcc, sidA, n); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		raw, _, err := l.Snapshot(hcc, sidA)
		if err != nil {
			t.Fatal(err)
		}
		// Every event appended after the snapshot is still there.
		got := 0
		for _, line := range bytes.Split(raw, []byte("\n")) {
			var e ledger.Event
			if json.Unmarshal(line, &e) == nil && e.Type == ledger.TypeMarkdown && !e.T.Before(at(round*1000+1)) && e.T.Before(at(round*1000+1000)) {
				got++
			}
		}
		if got != writers*each {
			t.Fatalf("round %d: %d of %d concurrent events survived Archive", round, got, writers*each)
		}
	}
}

// The ledger is content-free: only paths, ids and stats (I7, S13).
func TestLedgerLinesAreContentFree(t *testing.T) {
	t.Parallel()
	h := testkit.NewHome(t)
	marker := testkit.Marker(t)
	l := ledger.Open(h.Layout.SessionsDir)
	appendAll(t, l,
		ledger.Event{Type: ledger.TypeStart, SID: sidA, Proc: procP, Cwd: h.Root, Roots: []string{"root-acme"}, Source: "startup"},
		ledger.Event{Type: ledger.TypeMarkdown, SID: sidA, Path: filepath.Join(h.Root, "docs", "notes.md")},
		ledger.Event{Type: ledger.TypeEnd, SID: sidA, Reason: "other"},
	)
	if hits := testkit.GrepTree(t, h.Layout.SessionsDir, marker); len(hits) != 0 {
		t.Fatalf("marker found in %v", hits)
	}
	raw, _, err := l.Snapshot(hcc, sidA)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"v": true, "t": true, "type": true, "harness": true, "sid": true, "proc": true,
		"cwd": true, "path": true, "roots": true, "source": true, "reason": true}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("unexpected key %q in a ledger line", k)
			}
		}
	}
}

func TestTaintResolvesDeepestRootsFirst(t *testing.T) {
	t.Parallel()
	c := config.Default()
	c.Roots = []config.Root{
		{ID: "root-work", Path: "/u/work"},
		{ID: "root-acme", Path: "/u/work/acme"},
		{ID: "root-other", Path: "/u/other"},
	}
	got := ledger.Taint(c, "/u/work/acme/src/main.go", "/u/other/x", "/u/elsewhere")
	ids := make([]string, len(got))
	for i, r := range got {
		ids[i] = r.ID
	}
	if !reflect.DeepEqual(ids, []string{"root-acme", "root-other", "root-work"}) {
		t.Fatalf("Taint = %v", ids)
	}
	if got := ledger.Taint(c, "/u/elsewhere", "relative/path"); len(got) != 0 {
		t.Fatalf("Taint outside roots = %v", got)
	}
}

func TestIndexPutMergeLookup(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state", "projects")
	x := ledger.OpenIndex(dir, hcc)
	if x.Path != filepath.Join(dir, hcc+".json") {
		t.Fatalf("index path %s", x.Path)
	}
	if all, err := x.All(); err != nil || all != nil {
		t.Fatalf("empty index: %v %v", all, err)
	}
	p := ledger.Project{Harness: hcc, ConfigDir: "/u/cc", Slug: "-u-work-acme", Cwds: []string{"/u/work/acme"}, RootIDs: []string{"root-acme"}}
	if err := x.Put(p); err != nil {
		t.Fatal(err)
	}
	if err := x.Put(ledger.Project{ConfigDir: "/u/cc/", Slug: "-u-work-acme", Cwds: []string{"/u/work/acme/sub", "/u/work/acme"}, MemoryDir: "/u/cc/projects/-u-work-acme/memory"}); err != nil {
		t.Fatal(err)
	}
	if err := x.Put(ledger.Project{ConfigDir: "/u/cc", Slug: "-u-other", Cwds: []string{"/u/other"}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := x.Lookup("/u/cc", "-u-work-acme")
	if err != nil || !ok {
		t.Fatalf("Lookup: %v %v", ok, err)
	}
	want := ledger.Project{Harness: hcc, ConfigDir: "/u/cc", Slug: "-u-work-acme", Cwds: []string{"/u/work/acme", "/u/work/acme/sub"},
		RootIDs: []string{"root-acme"}, MemoryDir: "/u/cc/projects/-u-work-acme/memory"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %+v, want %+v", got, want)
	}
	if _, ok, _ := x.Lookup("/u/cc", "-u-missing"); ok {
		t.Fatal("Lookup found a missing project")
	}
	all, _ := x.All()
	if len(all) != 2 || all[0].Slug != "-u-other" {
		t.Fatalf("All = %+v", all)
	}
	fi, err := os.Stat(x.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("index mode %v %v", fi.Mode().Perm(), err)
	}
	for name, bad := range map[string]ledger.Project{
		"relative config dir": {ConfigDir: "cc", Slug: "s"},
		"slug with slash":     {ConfigDir: "/u/cc", Slug: "a/b"},
		"relative cwd":        {ConfigDir: "/u/cc", Slug: "s", Cwds: []string{"work"}},
		"relative memory dir": {ConfigDir: "/u/cc", Slug: "s", MemoryDir: "memory"},
	} {
		if err := x.Put(bad); err == nil {
			t.Errorf("%s: Put accepted it", name)
		}
	}
	os.WriteFile(x.Path, []byte("{broken"), 0o600)
	if _, err := x.All(); err == nil {
		t.Fatal("a corrupt index decoded")
	}
}

func TestIndexConcurrentPuts(t *testing.T) {
	t.Parallel()
	x := ledger.OpenIndex(filepath.Join(t.TempDir(), "projects"), hcc)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cwd := filepath.Join("/u/work/acme", string(rune('a'+i)))
			if err := x.Put(ledger.Project{ConfigDir: "/u/cc", Slug: "-u-work-acme", Cwds: []string{cwd}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	p, ok, err := x.Lookup("/u/cc", "-u-work-acme")
	if err != nil || !ok || len(p.Cwds) != 12 {
		t.Fatalf("after concurrent puts: %d cwds, %v %v", len(p.Cwds), ok, err)
	}
}
