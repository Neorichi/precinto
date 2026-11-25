package journal_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/sweep/journal"
)

func newJournal(t *testing.T) *journal.Journal {
	t.Helper()
	return journal.Open(filepath.Join(t.TempDir(), "state", "journal"))
}

func readOnDisk(t *testing.T, j *journal.Journal, id string) journal.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(j.Dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var r journal.Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBeginCreatesPreparedRecordPrivately(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != journal.PhasePrepared || r.V != journal.Version || r.PID != os.Getpid() || r.Started.IsZero() {
		t.Fatalf("record %+v", r)
	}
	st, err := fsx.Lstat(filepath.Join(j.Dir, r.ID+".json"))
	if err != nil || !st.IsRegular() || st.Perm() != 0o600 {
		t.Fatalf("record file %+v %v", st, err)
	}
	if dst, err := fsx.Lstat(j.Dir); err != nil || dst.Perm() != 0o700 {
		t.Fatalf("journal dir %+v %v", dst, err)
	}
	ents, _ := os.ReadDir(j.Dir)
	if len(ents) != 1 {
		t.Fatalf("temporaries left behind: %v", ents)
	}
	if got := readOnDisk(t, j, r.ID); got.Phase != journal.PhasePrepared || got.Unit != r.Unit {
		t.Fatalf("on disk %+v", got)
	}
}

func TestCapsuleNameRecordedAtPrepared(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "aa")
	if err != nil {
		t.Fatal(err)
	}
	r.Tmp, r.Capsule, r.Gen = ".op-x", "g000007.pcap", 7
	r.Files = []journal.File{{Base: "claude_config", Rel: "projects/p/s.jsonl", Snap: fsx.Stat{Ino: 9, Size: 3}}}
	if err := j.Save(r); err != nil {
		t.Fatal(err)
	}
	got := readOnDisk(t, j, r.ID)
	if got.Phase != journal.PhasePrepared || got.Capsule != "g000007.pcap" || got.Tmp != ".op-x" || got.Gen != 7 {
		t.Fatalf("prepared record does not name the capsule: %+v", got)
	}
	if len(got.Files) != 1 || got.Files[0].Snap.Ino != 9 || got.Files[0].Done {
		t.Fatalf("files %+v", got.Files)
	}
}

func TestAdvanceAndHistoryOffsetsRoundTrip(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindHistoryRotate, "claude-code", "hh")
	if err != nil {
		t.Fatal(err)
	}
	r.Hold, r.HoldSize = ".precinto-hold-x", 100
	if err := j.Advance(r, journal.PhaseHeld); err != nil {
		t.Fatal(err)
	}
	r.Pending = 140
	if err := j.Advance(r, journal.PhaseSealed); err != nil {
		t.Fatal(err)
	}
	r.Offset, r.NewBase = 140, 60
	if err := j.Advance(r, journal.PhaseRewritten); err != nil {
		t.Fatal(err)
	}
	r.Pending = 200
	if err := j.Save(r); err != nil {
		t.Fatal(err)
	}
	p, err := j.Pending()
	if err != nil || len(p) != 1 {
		t.Fatalf("pending %v %v", p, err)
	}
	got := p[0]
	if got.Phase != journal.PhaseRewritten || got.Hold != ".precinto-hold-x" || got.HoldSize != 100 ||
		got.Offset != 140 || got.Pending != 200 || got.NewBase != 60 {
		t.Fatalf("history offsets did not round-trip: %+v", got)
	}
}

func TestPendingOrderingAndDone(t *testing.T) {
	j := newJournal(t)
	var ids []string
	for i := 0; i < 5; i++ {
		r, err := j.Begin(journal.KindRestore, "claude-code", strings.Repeat(string(rune('a'+i)), 2))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	p, err := j.Pending()
	if err != nil || len(p) != 5 {
		t.Fatalf("pending %d %v", len(p), err)
	}
	for i, r := range p {
		if r.ID != ids[i] {
			t.Fatalf("pending[%d] = %s, want %s (oldest first)", i, r.ID, ids[i])
		}
	}
	if err := j.Done(p[2]); err != nil {
		t.Fatal(err)
	}
	if err := j.Done(p[2]); err != nil {
		t.Fatalf("second Done: %v", err)
	}
	if _, err := os.Stat(filepath.Join(j.Dir, ids[2]+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record still on disk: %v", err)
	}
	p, _ = j.Pending()
	if len(p) != 4 {
		t.Fatalf("pending after Done: %d", len(p))
	}
	for _, r := range p {
		if r.ID == ids[2] {
			t.Fatal("done record still pending")
		}
	}
}

func TestBeginConflictsOnTheSameUnit(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Begin(journal.KindRestore, "claude-code", "u1"); !errors.Is(err, journal.ErrConflict) {
		t.Fatalf("second Begin on the unit: %v, want ErrConflict", err)
	}
	if _, err := j.Begin(journal.KindSeal, "claude-code", "u2"); err != nil {
		t.Fatalf("another unit: %v", err)
	}
	if err := j.Done(r); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Begin(journal.KindSeal, "claude-code", "u1"); err != nil {
		t.Fatalf("after Done: %v", err)
	}
}

func TestPendingReportsUnreadableRecordsButKeepsTheRest(t *testing.T) {
	j := newJournal(t)
	good, err := j.Begin(journal.KindSeal, "claude-code", "u1")
	if err != nil {
		t.Fatal(err)
	}
	bad := journal.NewID()
	if err := os.WriteFile(filepath.Join(j.Dir, bad+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := journal.NewID()
	if err := os.Symlink(filepath.Join(j.Dir, good.ID+".json"), filepath.Join(j.Dir, link+".json")); err != nil {
		t.Fatal(err)
	}
	// Foreign names and temporaries are ignored silently.
	_ = os.WriteFile(filepath.Join(j.Dir, "notes.txt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(j.Dir, ".x.json.tmp-1-0"), []byte("x"), 0o600)
	p, err := j.Pending()
	if err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), link) {
		t.Fatalf("unreadable records not reported: %v", err)
	}
	if len(p) != 1 || p[0].ID != good.ID {
		t.Fatalf("readable record lost: %+v", p)
	}
}

func TestDoneMarkedRecordIsNotPending(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Advance(r, journal.PhaseDone); err != nil {
		t.Fatal(err)
	}
	if p, err := j.Pending(); err != nil || len(p) != 0 {
		t.Fatalf("pending %v %v", p, err)
	}
}

func TestMissingDirectoryHasNothingPending(t *testing.T) {
	j := journal.Open(filepath.Join(t.TempDir(), "absent"))
	if p, err := j.Pending(); err != nil || len(p) != 0 {
		t.Fatalf("pending %v %v", p, err)
	}
}

func TestSaveRejectsForeignIDs(t *testing.T) {
	j := newJournal(t)
	for _, id := range []string{"", "../x", "0000000000000000-zzzzzzzz", "x.json"} {
		if err := j.Save(&journal.Record{ID: id}); err == nil {
			t.Errorf("Save accepted id %q", id)
		}
		if err := j.Done(&journal.Record{ID: id}); err == nil {
			t.Errorf("Done accepted id %q", id)
		}
	}
}

func TestNewIDIsSortableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	prev := ""
	for i := 0; i < 1000; i++ {
		id := journal.NewID()
		if seen[id] || id <= prev {
			t.Fatalf("id %q not unique/increasing after %q", id, prev)
		}
		seen[id] = true
		prev = id
	}
}

func TestBeginRefusesAPublicDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Open(dir).Begin(journal.KindSeal, "h", "u"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Fatalf("Begin in a 0755 directory: %v", err)
	}
}

// CC-25: a file's base id and its absolute directory are separate fields,
// and the ledger snapshot of a seal round-trips for keyless recovery.
func TestFileDirAndLedgerRoundTrip(t *testing.T) {
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "uu")
	if err != nil {
		t.Fatal(err)
	}
	r.Files = []journal.File{{Base: "claude_config", Dir: "/abs/with|pipe/claude", Rel: "projects/P/s.jsonl"}}
	r.LedgerSID, r.LedgerN = "00000000-0000-4000-8000-000000000001", 4096
	if err := j.Save(r); err != nil {
		t.Fatal(err)
	}
	disk := readOnDisk(t, j, r.ID)
	if len(disk.Files) != 1 || disk.Files[0].Base != "claude_config" || disk.Files[0].Dir != "/abs/with|pipe/claude" ||
		disk.LedgerSID != r.LedgerSID || disk.LedgerN != 4096 {
		t.Fatalf("record on disk: %+v", disk)
	}
	b, err := os.ReadFile(filepath.Join(j.Dir, r.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"dir":`, `"ledger_sid":`, `"ledger_n":`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("record lacks %s", key)
		}
	}
}
