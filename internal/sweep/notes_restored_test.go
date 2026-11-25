package sweep

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/testkit"
)

// sealedNoteWithoutWriter seals a note, then forgets its writer: the
// session's ledger moved into its capsule (S13) and the session was not
// one of the restore_recent ones, so nothing but precinto's own restore
// names the note any more.
func (te *testEnv) sealedNoteWithoutWriter(rel, body string) (string, string) {
	te.t.Helper()
	p := te.note(rel, body)
	key := te.noteKey(rel)
	if res := outcome(te.t, te.sealNotes(), key); res.Outcome != OutSealed {
		te.t.Fatalf("seal %+v", res)
	}
	te.ledger.sessions["claude-code"] = nil
	return p, key
}

func ageNote(t *testing.T, p string) {
	t.Helper()
	old := testkit.Epoch.Add(-time.Hour)
	mustNoErr(t, os.Chtimes(p, old, old))
}

// D83 (DATA-2): a note restored at unlock is sealed again at the next
// lock although its writer session stayed sealed: unchanged, so no new
// generation; the marker is back and the plaintext gone. While it is
// plaintext the summary counts it.
func TestRestoredNoteIsSealedAgainWithoutItsWriter(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p, key := te.sealedNoteWithoutWriter("docs/plan.md", "# plan\n")
	if res := outcome(t, te.restoreNotes(), key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	ageNote(t, p)
	sum, err := te.run().plaintextSummary(tctx(t))
	mustNoErr(t, err)
	notes := 0
	for _, s := range sum {
		notes += s.ByReason["notes"]
	}
	if notes != 1 {
		t.Fatalf("restored note not counted as plaintext: %+v", sum)
	}
	res := outcome(t, te.sealNotes(), key)
	if res.Outcome != OutUnchanged {
		t.Fatalf("re-seal %+v", res)
	}
	if exists(p) {
		t.Fatal("restored note left in plaintext after the lock")
	}
	if k, err := ParseMarker(p + markerSuffix); err != nil || k != key {
		t.Fatalf("marker %q %v", k, err)
	}
	if n := len(te.logged(key)); n != 1 {
		t.Fatalf("%d generations, want 1", n)
	}
}

// D83: a note restored at a moved marker's location is dropped under the
// unit it was restored from and comes back there; once edited it is
// sealed as a note of its new path, its content kept.
func TestNoteRestoredAtAMovedMarkerIsSealedAgain(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p, key := te.sealedNoteWithoutWriter("docs/plan.md", "# plan\n")
	moved := filepath.Join(te.h.Root, "archive", "plan.md")
	mustNoErr(t, os.MkdirAll(filepath.Dir(moved), 0o700))
	mustNoErr(t, os.Rename(p+markerSuffix, moved+markerSuffix))
	if res := outcome(t, te.restoreNotes(), key); res.Outcome != OutRestored || !exists(moved) {
		t.Fatalf("restore %+v", res)
	}
	ageNote(t, moved)
	res := outcome(t, te.sealNotes(), key)
	if res.Outcome != OutUnchanged {
		t.Fatalf("re-seal %+v", res)
	}
	if exists(moved) || exists(p) {
		t.Fatal("note left in plaintext")
	}
	if k, err := ParseMarker(moved + markerSuffix); err != nil || k != key {
		t.Fatalf("marker %q %v", k, err)
	}
	if n := len(te.logged(key)); n != 1 || len(te.logged(te.noteKey("archive/plan.md"))) != 0 {
		t.Fatal("a new unit or generation was made for an unchanged note")
	}
	// The next unlock brings it back at the moved location.
	te.restoreNotes()
	if string(readFile(t, moved)) != "# plan\n" || exists(p) {
		t.Fatal("not restored at the moved marker")
	}
	// Edited there: a note of its own path, content kept.
	appendLines(t, moved, "more")
	ageNote(t, moved)
	own := te.noteKey("archive/plan.md")
	res = outcome(t, te.sealNotes(), own)
	if res.Outcome != OutSealed {
		t.Fatalf("edited re-seal %+v", res)
	}
	if exists(moved) || len(te.logged(key)) != 1 {
		t.Fatal("edited note left in plaintext or sealed into the unit of another path")
	}
}
