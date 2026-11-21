package sweep

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/testkit"
)

// note writes a Markdown file in the root (mtime outside the quiet
// window) and lists it in an ended session's ledger.
func (te *testEnv) note(rel, body string) string {
	te.t.Helper()
	p := filepath.Join(te.h.Root, filepath.FromSlash(rel))
	writeAt(te.t, p, []byte(body))
	old := testkit.Epoch.Add(-time.Hour)
	mustNoErr(te.t, os.Chtimes(p, old, old))
	sessions := te.ledger.sessions["claude-code"]
	sessions = append(sessions, ledger.Session{Harness: "claude-code", SID: sid1, RootIDs: []string{rootID}, Markdown: []string{p}, Ended: true})
	te.ledger.sessions["claude-code"] = sessions
	return p
}

func (te *testEnv) root() config.Root {
	r, ok := te.e.Cfg.RootByID(rootID)
	if !ok {
		te.t.Fatal("no root")
	}
	return r
}

func (te *testEnv) sealNotes() *Report {
	te.t.Helper()
	r := te.run()
	root := te.root()
	r.sealMarkdown(context.Background(), root, Options{}, r.noteCandidates(context.Background(), root))
	return r.finish()
}

func (te *testEnv) noteKey(rel string) string {
	k, err := harness.UnitKeyFor(te.e.Harness.Salt, capsule.KindMarkdown, mdHarness, "", rootID, rel)
	mustNoErr(te.t, err)
	return k
}

func (te *testEnv) restoreNotes() *Report {
	te.t.Helper()
	rep, err := te.run().restoreMarkdown(context.Background(), te.keys, te.root())
	mustNoErr(te.t, err)
	return rep
}

func TestMarkerTextAndParseMarker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := strings.Repeat("ab", 16)
	good := filepath.Join(dir, "notes.md.precinto")
	writeAt(t, good, MarkerText(key))
	if k, err := ParseMarker(good); err != nil || k != key {
		t.Fatalf("ParseMarker = %q, %v", k, err)
	}
	for name, content := range map[string][]byte{
		"extra.md.precinto":   append(MarkerText(key), "more\n"...),
		"badkey.md.precinto":  MarkerText("XYZ"),
		"empty.md.precinto":   nil,
		"huge.md.precinto":    bytes.Repeat([]byte("x"), 5000),
		"script.sh.precinto":  MarkerText(key),
		"notes.md":            MarkerText(key),
		"nonewline.md.precin": MarkerText(key),
	} {
		p := filepath.Join(dir, name)
		writeAt(t, p, content)
		if _, err := ParseMarker(p); !errors.Is(err, ErrNotMarker) {
			t.Errorf("%s: %v, want ErrNotMarker", name, err)
		}
	}
	link := filepath.Join(dir, "link.md.precinto")
	mustNoErr(t, os.Symlink(good, link))
	if _, err := ParseMarker(link); !errors.Is(err, ErrNotMarker) {
		t.Errorf("symlinked marker: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.md.precinto")
	mustNoErr(t, mkfifo(fifo))
	if _, err := ParseMarker(fifo); !errors.Is(err, ErrNotMarker) {
		t.Errorf("FIFO marker: %v", err)
	}
}

// D16: the capsule goes to the store, a marker (no ciphertext) replaces
// the note in the tree, the plaintext goes.
func TestSealNoteWritesAMarker(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	mrk := testkit.Marker(t)
	p := te.note("docs/notes.md", "# notes\n"+mrk+"\n")
	key := te.noteKey("docs/notes.md")
	rep := te.sealNotes()
	if res := outcome(t, rep, key); res.Outcome != OutSealed || res.Kind != capsule.KindMarkdown {
		t.Fatalf("seal %+v", res)
	}
	if exists(p) {
		t.Fatal("note plaintext left")
	}
	m := p + ".precinto"
	if k, err := ParseMarker(m); err != nil || k != key {
		t.Fatalf("marker %q %v", k, err)
	}
	if st, _ := fsx.Lstat(m); st.Perm() != 0o600 {
		t.Fatalf("marker mode %v", st.Perm())
	}
	if en := te.logged(key); len(en) != 1 || !strings.HasPrefix(en[0].Path, "md/"+key+"/") {
		t.Fatalf("log %+v", en)
	}
	// I4: no ciphertext in the tree; no content in precinto metadata.
	if bytes.Contains(readFile(t, m), []byte(fakeMagic)) {
		t.Fatal("ciphertext in the marker")
	}
	if hits := testkit.GrepTree(t, te.h.Base, mrk, "capsules"); len(hits) != 0 {
		t.Fatalf("note content leaked: %v", hits)
	}
	// Restore at unlock: back at the marker location, marker removed.
	rep = te.restoreNotes()
	if res := outcome(t, rep, key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	if !strings.Contains(string(readFile(t, p)), mrk) || exists(m) {
		t.Fatal("note not restored in place or marker left")
	}
	// D10 for notes: unchanged re-seal makes no new generation; an edit
	// makes a successor.
	rep = te.sealNotes()
	if res := outcome(t, rep, key); res.Outcome != OutUnchanged {
		t.Fatalf("unchanged re-seal %+v", res)
	}
	te.restoreNotes()
	appendLines(t, p, "more")
	old := testkit.Epoch.Add(-time.Hour)
	mustNoErr(t, os.Chtimes(p, old, old))
	rep = te.sealNotes()
	if res := outcome(t, rep, key); res.Gen != 2 || res.Lineage != capsule.LineageSuccessor {
		t.Fatalf("edited re-seal %+v", res)
	}
}

// NOTE-1 / D51: after `git clean` removed the marker, the note comes back
// at its authenticated original relpath.
func TestNoteRestoresAtItsRelpathWithoutAMarker(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "body\n")
	te.sealNotes()
	mustNoErr(t, os.Remove(p+".precinto"))
	rep := te.restoreNotes()
	res := outcome(t, rep, te.noteKey("docs/notes.md"))
	if res.Outcome != OutRestored || res.Detail != "restored at its original path" {
		t.Fatalf("restore %+v", res)
	}
	if string(readFile(t, p)) != "body\n" {
		t.Fatal("not restored at the relpath")
	}
}

// A moved marker (same note name) moves the restore target (D16).
func TestNoteFollowsAMovedMarker(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "body\n")
	te.sealNotes()
	moved := filepath.Join(te.h.Root, "archive", "notes.md.precinto")
	mustNoErr(t, os.MkdirAll(filepath.Dir(moved), 0o700))
	mustNoErr(t, os.Rename(p+".precinto", moved))
	te.restoreNotes()
	if string(readFile(t, filepath.Join(te.h.Root, "archive", "notes.md"))) != "body\n" || exists(p) || exists(moved) {
		t.Fatal("note did not follow its marker")
	}
}

// NOTE-2: plaintext at the note path (a branch switch): conflict copy,
// existing file untouched, capsule kept.
func TestNoteConflictKeepsBoth(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "sealed version\n")
	te.sealNotes()
	writeAt(t, p, []byte("branch version\n"))
	rep := te.restoreNotes()
	key := te.noteKey("docs/notes.md")
	if res := outcome(t, rep, key); res.Outcome != OutConflict {
		t.Fatalf("restore %+v", res)
	}
	if string(readFile(t, p)) != "branch version\n" {
		t.Fatal("I11: existing plaintext replaced")
	}
	c := filepath.Join(te.h.Root, "docs", "notes.conflict-"+te.h.Clock.Now().UTC().Format("20060102-1504")+".md")
	if string(readFile(t, c)) != "sealed version\n" {
		t.Fatal("no conflict copy")
	}
	if len(te.logged(key)) != 1 {
		t.Fatal("capsule not kept")
	}
	// resolve --keep plaintext: the copy goes; the capsule keeps it.
	rep, err := te.run().resolve(context.Background(), te.keys, c, "plaintext")
	mustNoErr(t, err)
	if rep.Count(OutRestored) != 1 || exists(c) || string(readFile(t, p)) != "branch version\n" {
		t.Fatalf("resolve %+v", rep.Units)
	}
}

func TestResolveKeepCapsuleRetainsThePlaintext(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "sealed version\n")
	te.sealNotes()
	writeAt(t, p, []byte("branch version\n"))
	te.restoreNotes()
	key := te.noteKey("docs/notes.md")
	rep, err := te.run().resolve(context.Background(), te.keys, p, "capsule")
	mustNoErr(t, err)
	if rep.Count(OutRestored) != 1 {
		t.Fatalf("resolve %+v", rep.Units)
	}
	if string(readFile(t, p)) != "sealed version\n" {
		t.Fatal("capsule version not in place")
	}
	en := te.logged(key)
	if len(en) != 2 || capsule.Lineage(en[1].Lineage) != capsule.LineageDiverged {
		t.Fatalf("the other side was not retained as a generation: %+v", en)
	}
	if _, err := te.run().resolve(context.Background(), te.keys, p, "both"); err == nil {
		t.Fatal("unknown --keep accepted")
	}
}

// NOTE-3 / D17: a live session that wrote the note keeps it plaintext.
func TestNoteOfALiveSessionIsNotSealed(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	p := te.note("docs/notes.md", "body\n")
	u := te.scanSession(sid1)
	te.claude.mdPaths[sid1] = []string{p}
	te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonLedgerProc}}
	rep := te.sealNotes()
	if res := outcome(t, rep, te.noteKey("docs/notes.md")); res.Outcome != OutLive {
		t.Fatalf("result %+v", res)
	}
	if !exists(p) || exists(p+".precinto") {
		t.Fatal("I1: a live note was sealed")
	}
}

func TestNotePolicyExclusions(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	readme := te.note("README.md", "readme\n")
	skill := te.note("tools/x/SKILL.md", "skill\n")
	vendored := te.note("node_modules/pkg/notes.md", "dep\n")
	txt := te.note("docs/data.txt", "not markdown\n")
	mustNoErr(t, os.MkdirAll(filepath.Join(te.h.Root, ".git"), 0o700))
	tracked := te.note("docs/tracked.md", "tracked\n")
	te.git.tracked[te.h.Root] = map[string]bool{"docs/tracked.md": true}
	free := te.note("docs/free.md", "free\n")
	rep := te.sealNotes()
	for _, p := range []string{readme, skill, vendored, txt, tracked} {
		if !exists(p) {
			t.Errorf("%s sealed", filepath.Base(p))
		}
	}
	if res := outcome(t, rep, te.noteKey("docs/tracked.md")); res.Detail != "git-tracked" {
		t.Fatalf("tracked %+v", res)
	}
	if exists(free) || te.git.calls != 1 {
		t.Fatalf("untracked note not sealed (git called %d times)", te.git.calls)
	}
	// Any git failure means "tracked": nothing is sealed (S21, IM22).
	te2 := newTestEnv(t)
	mustNoErr(t, os.MkdirAll(filepath.Join(te2.h.Root, ".git"), 0o700))
	n := te2.note("docs/n.md", "x\n")
	te2.git.err = errors.New("git broke")
	te2.sealNotes()
	if !exists(n) {
		t.Fatal("sealed although git failed")
	}
}

func TestNotesWaitForBusySessionsAndEnd(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "x\n")
	te.busy.busy = true
	rep := te.sealNotes()
	if !exists(p) || rep.Count(OutSkipped) != 1 || !strings.HasPrefix(rep.Units[0].Detail, "deferred") {
		t.Fatalf("busy root: %+v", rep.Units)
	}
	te.busy.busy = false
	te.e.Cfg.Policy.MDSealOn = config.MDSealOnEnd
	te.ledger.sessions["claude-code"][0].Ended = false
	rep = te.sealNotes()
	if !exists(p) {
		t.Fatalf("md_seal_on=end sealed a note of a running session: %+v", rep.Units)
	}
	te.ledger.sessions["claude-code"][0].Ended = true
	te.sealNotes()
	if exists(p) {
		t.Fatal("not sealed after its session ended")
	}
}

func TestNotesQuietWindowAndMDAll(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.e.Cfg.Policy.QuietWindow = config.Duration(2 * time.Minute)
	p := te.note("docs/fresh.md", "x\n")
	now := te.h.Clock.Now()
	mustNoErr(t, os.Chtimes(p, now, now))
	te.sealNotes()
	if !exists(p) {
		t.Fatal("a note changed within the quiet window was sealed")
	}
	// md = "all" finds notes no ledger mentions.
	te2 := newTestEnv(t)
	for i := range te2.e.Cfg.Roots {
		te2.e.Cfg.Roots[i].MD = config.MDAll
	}
	q := filepath.Join(te2.h.Root, "bash", "made.md")
	writeAt(t, q, []byte("made by bash\n"))
	old := testkit.Epoch.Add(-time.Hour)
	mustNoErr(t, os.Chtimes(q, old, old))
	te2.sealNotes()
	if exists(q) || !exists(q+".precinto") {
		t.Fatal("md=all did not seal an unlisted note")
	}
}

// SEC-3: a marker pointing at another note's unit, a non-note marker and
// a marker outside the root are rejected.
func TestMarkersCannotRedirectNotes(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/secret.md", "secret\n")
	te.sealNotes()
	key := te.noteKey("docs/secret.md")
	// Remove the real marker; plant one at another name naming the unit.
	mustNoErr(t, os.Remove(p+".precinto"))
	evil := filepath.Join(te.h.Root, "public", "readme.md.precinto")
	writeAt(t, evil, MarkerText(key))
	sh := filepath.Join(te.h.Root, "a.sh.precinto")
	writeAt(t, sh, MarkerText(key))
	te.restoreNotes()
	if exists(filepath.Join(te.h.Root, "public", "readme.md")) || exists(filepath.Join(te.h.Root, "a.sh")) {
		t.Fatal("a marker redirected the note")
	}
	if string(readFile(t, p)) != "secret\n" {
		t.Fatal("note not restored at its own relpath")
	}
	if !exists(evil) {
		t.Fatal("a foreign marker was removed")
	}
	// `precinto open` of such a marker is refused.
	mustNoErr(t, os.Remove(p))
	writeAt(t, p+".precinto", MarkerText(key))
	te2 := te.run()
	rep, err := te2.openNotes(context.Background(), te.keys, []string{evil})
	mustNoErr(t, err)
	if res := outcome(t, rep, key); res.Outcome != OutFailed {
		t.Fatalf("open of a redirecting marker %+v", res)
	}
	// Markers naming unlogged units are ignored.
	writeAt(t, filepath.Join(te.h.Root, "x.md.precinto"), MarkerText(strings.Repeat("cd", 16)))
	rep, _ = te.run().openNotes(context.Background(), te.keys, []string{filepath.Join(te.h.Root, "x.md.precinto")})
	if rep.Count(OutFailed) != 1 || exists(filepath.Join(te.h.Root, "x.md")) {
		t.Fatalf("unlogged marker %+v", rep.Units)
	}
}

func TestCatAndOpenNotes(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "the body\n")
	te.sealNotes()
	var out bytes.Buffer
	mustNoErr(t, te.run().catNote(context.Background(), te.keys, p+".precinto", &out))
	if out.String() != "the body\n" {
		t.Fatalf("cat %q", out.String())
	}
	if te.keys.purposes[len(te.keys.purposes)-1] != "cat" {
		t.Fatalf("purpose %v", te.keys.purposes)
	}
	if exists(p) {
		t.Fatal("cat placed plaintext")
	}
	if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
		t.Fatal("cat left staging")
	}
	rep, err := te.run().openNotes(context.Background(), te.keys, []string{p + ".precinto"})
	mustNoErr(t, err)
	if rep.Count(OutRestored) != 1 || string(readFile(t, p)) != "the body\n" {
		t.Fatalf("open %+v", rep.Units)
	}
	if te.keys.purposes[len(te.keys.purposes)-1] != "open" {
		t.Fatalf("purpose %v", te.keys.purposes)
	}
	if err := te.run().catNote(context.Background(), te.keys, p, &out); !errors.Is(err, ErrNotMarker) {
		t.Fatalf("cat of a non-marker: %v", err)
	}
}

func TestGlobMatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		pat, rel string
		want     bool
	}{
		{"README.md", "README.md", true},
		{"README.md", "docs/README.md", true},
		{"**/SKILL.md", "a/b/SKILL.md", true},
		{".git/**", ".git/x.md", true},
		{".git/**", "sub/.git/x.md", true},
		{"node_modules/**", "a/node_modules/b/c.md", true},
		{"docs/*.md", "docs/x.md", true},
		{"docs/*.md", "docs/sub/x.md", false},
		{"README.md", "READMEX.md", false},
	} {
		if got := globMatch(tc.pat, tc.rel); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v", tc.pat, tc.rel, got)
		}
	}
}

func TestNoteTargetRules(t *testing.T) {
	t.Parallel()
	for rel, want := range map[string]bool{
		"docs/notes.md": true, "a.mdx": true, "b.MARKDOWN": true, "a.sh": false, "../x.md": false,
		".git/x.md": false, "x/.claude/y.md": false, "node_modules/a.md": false, "./a.md": false,
	} {
		if got := noteTargetOK(rel); got != want {
			t.Errorf("noteTargetOK(%q) = %v", rel, got)
		}
	}
}

// SPEC §11.2: a note target whose parent is a deny-listed directory under
// another spelling (case-insensitive volumes) is refused by identity.
func TestNoteTargetAliasCheck(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	mustNoErr(t, os.MkdirAll(filepath.Join(te.h.Root, ".vscode"), 0o700))
	mustNoErr(t, os.MkdirAll(filepath.Join(te.h.Root, "docs"), 0o700))
	d, err := te.fs.OpenBase(te.h.Root)
	mustNoErr(t, err)
	if !noteTargetAliasFree(d, "docs/x.md") || !noteTargetAliasFree(d, "new/dir/x.md") {
		t.Fatal("ordinary targets refused")
	}
	if _, err := os.Lstat(filepath.Join(te.h.Root, ".VSCODE")); err == nil {
		// Case-insensitive volume: the alias resolves to .vscode.
		if noteTargetAliasFree(d, ".VSCODE/x.md") {
			t.Fatal("an alias of a deny-listed directory passed")
		}
	} else {
		t.Log("case-sensitive volume: alias check only by name")
	}
}
