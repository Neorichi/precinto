package sweep

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
)

// TestPlacementTableGolden renders the decision of the placement table
// (SPEC §11.3, D11) for every policy and situation; the golden file is the
// reviewed table (regenerate with -update).
func TestPlacementTableGolden(t *testing.T) {
	t.Parallel()
	situations := []struct {
		name string
		f    pairFacts
	}{
		{"equal bytes", pairFacts{CSize: 10, FSize: 10, CSHA: "a", FSHA: "a"}},
		{"F starts with C (superset)", pairFacts{CSize: 10, FSize: 20, CSHA: "a", FSHA: "b", FStartsWithC: true}},
		{"C starts with F (stale prefix)", pairFacts{CSize: 20, FSize: 10, CSHA: "a", FSHA: "b", CStartsWithF: true}},
		{"linked classic fragment", pairFacts{CSize: 20, FSize: 5, CSHA: "a", FSHA: "b", Linked: true}},
		{"unrelated", pairFacts{CSize: 20, FSize: 5, CSHA: "a", FSHA: "b"}},
	}
	policies := []harness.Placement{harness.PlaceExact, harness.PlaceJSONLAppend, harness.PlaceLineUnion,
		harness.PlaceSQLiteGroup, harness.PlaceMarkdown, ""}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# placement table (SPEC §11.3): policy | situation -> action\n")
	for _, p := range policies {
		for _, s := range situations {
			f := s.f
			f.Policy = p
			name := string(p)
			if name == "" {
				name = "(unknown)"
			}
			fmt.Fprintf(&b, "%-13s | %-31s -> %s\n", name, s.name, decidePlacement(f))
		}
	}
	testkit.Golden(t, "placement.golden", b.Bytes())
}

func TestLinkedFragmentRule(t *testing.T) {
	t.Parallel()
	c := claude.Links{UUIDs: map[string]bool{"u1": true, "u2": true}, Valid: true}
	for _, tc := range []struct {
		name string
		f    claude.Links
		want bool
	}{
		{"parent in C, disjoint", claude.Links{UUIDs: map[string]bool{"u3": true}, FirstParent: "u2", Valid: true}, true},
		{"logical parent in C", claude.Links{UUIDs: map[string]bool{"u3": true}, FirstLogicalParent: "u1", Valid: true}, true},
		{"parent outside C", claude.Links{UUIDs: map[string]bool{"u3": true}, FirstParent: "zz", Valid: true}, false},
		{"overlapping uuids", claude.Links{UUIDs: map[string]bool{"u2": true, "u3": true}, FirstParent: "u1", Valid: true}, false},
		{"unparseable F", claude.Links{UUIDs: map[string]bool{"u3": true}, FirstParent: "u1"}, false},
	} {
		if got := linkedFragment(c, tc.f); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	if linkedFragment(claude.Links{UUIDs: c.UUIDs}, claude.Links{UUIDs: map[string]bool{"u3": true}, FirstParent: "u1", Valid: true}) {
		t.Error("unparseable C merged")
	}
}

// mapHasher hashes from fixed contents.
type mapHasher map[string]string

func (m mapHasher) prefix(f harness.File, n int64) (string, error) {
	s := m[f.Rel]
	if int64(len(s)) < n {
		return "", fsx.ErrChanged
	}
	return sum([]byte(s[:n])), nil
}

// TestLineageTable is the lineage table of SPEC §10.4 over (fresh,
// successor, partial, diverged) and the unchanged decision (D10, D42).
func TestLineageTable(t *testing.T) {
	t.Parallel()
	file := func(rel string, size int64, ino uint64) harness.File {
		return harness.File{Base: capsule.BaseClaudeConfig, Rel: rel, Snap: fsx.Stat{Ino: ino, Size: size, MtimeNS: 1}}
	}
	// appendOnly is an append-only (JSONL) file: changed in place, it is a
	// real divergence; an exact-placement file precinto placed and that was
	// rewritten in place supersedes (D87).
	appendOnly := func(f harness.File) harness.File {
		f.Append, f.Placement = true, harness.PlaceJSONLAppend
		return f
	}
	rf := func(rel, content string, ino uint64) ReceiptFile {
		return ReceiptFile{Base: capsule.BaseClaudeConfig, Rel: rel, Snap: fsx.Stat{Ino: ino, Size: int64(len(content)), MtimeNS: 1},
			SHA256: sum([]byte(content)), Size: int64(len(content)), FromGen: 3}
	}
	gens := []capslog.Entry{{Gen: 3, Lineage: "fresh"}}
	rd := &receiptDisk{Receipt: Receipt{Gen: 3, Files: []ReceiptFile{rf("a", "aaaa", 1), rf("b", "bb", 2)}}}
	absentRD := &receiptDisk{Receipt: Receipt{Gen: 3, Files: []ReceiptFile{rf("a", "aaaa", 1),
		{Base: capsule.BaseClaudeConfig, Rel: "b", SHA256: sum([]byte("bb")), Size: 2, FromGen: 3, Absent: true}}}}
	for _, tc := range []struct {
		name      string
		files     []harness.File
		content   mapHasher
		rd        *receiptDisk
		logged    []capslog.Entry
		lineage   capsule.Lineage
		parent    uint64
		unchanged bool
	}{
		{"no receipt, no generation", []harness.File{file("a", 4, 9)}, mapHasher{"a": "aaaa"}, nil, nil, capsule.LineageFresh, 0, false},
		{"no receipt, generations exist", []harness.File{file("a", 4, 9)}, mapHasher{"a": "aaaa"}, nil, gens, capsule.LineageDiverged, 3, false},
		{"identical (identity)", []harness.File{file("a", 4, 1), file("b", 2, 2)}, nil, rd, gens, capsule.LineageSuccessor, 3, true},
		{"identical (hash, new inode)", []harness.File{file("a", 4, 7), file("b", 2, 8)}, mapHasher{"a": "aaaa", "b": "bb"}, rd, gens, capsule.LineageSuccessor, 3, true},
		{"append-only growth", []harness.File{file("a", 6, 1), file("b", 2, 2)}, mapHasher{"a": "aaaaXY"}, rd, gens, capsule.LineageSuccessor, 3, false},
		{"one file missing", []harness.File{file("a", 4, 1)}, nil, rd, gens, capsule.LineagePartial, 3, true},
		{"changed in place", []harness.File{appendOnly(file("a", 4, 7)), file("b", 2, 2)}, mapHasher{"a": "zzzz"}, rd, gens, capsule.LineageDiverged, 3, false},
		{"shrunk", []harness.File{appendOnly(file("a", 2, 7)), file("b", 2, 2)}, mapHasher{"a": "aa"}, rd, gens, capsule.LineageDiverged, 3, false},
		{"exact file rewritten after its restore (D87)", []harness.File{file("a", 4, 7), file("b", 2, 2)}, mapHasher{"a": "zzzz"}, rd, gens, capsule.LineageSuccessor, 3, false},
		{"exact file shrunk after its restore (D87)", []harness.File{file("a", 2, 7), file("b", 2, 2)}, mapHasher{"a": "aa"}, rd, gens, capsule.LineageSuccessor, 3, false},
		{"exact rewrite with a file missing (D87)", []harness.File{file("a", 4, 7)}, mapHasher{"a": "zzzz"}, rd, gens, capsule.LineagePartial, 3, false},
		{"absent file still absent (D85)", []harness.File{file("a", 4, 1)}, nil, absentRD, gens, capsule.LineagePartial, 3, true},
		{"absent file back with other bytes (D85)", []harness.File{file("a", 4, 1), file("b", 2, 9)}, mapHasher{"b": "zz"}, absentRD, gens, capsule.LineageDiverged, 3, false},
		{"absent file back with its bytes (D85)", []harness.File{file("a", 4, 1), file("b", 2, 9)}, mapHasher{"b": "bb"}, absentRD, gens, capsule.LineageSuccessor, 3, true},
		{"new file added", []harness.File{file("a", 4, 1), file("b", 2, 2), file("c", 1, 3)}, mapHasher{"c": "c"}, rd, gens, capsule.LineageSuccessor, 3, false},
		{"receipt generation pruned", []harness.File{file("a", 4, 1), file("b", 2, 2)}, nil, rd, []capslog.Entry{{Gen: 9}}, capsule.LineageSuccessor, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.content
			if h == nil {
				h = mapHasher{}
			}
			lp, err := planLineage(tc.files, tc.rd, tc.logged, h)
			if err != nil {
				t.Fatal(err)
			}
			if lp.Lineage != tc.lineage || lp.Parent != tc.parent || lp.Unchanged != tc.unchanged {
				t.Fatalf("got %s parent %d unchanged %v, want %s %d %v", lp.Lineage, lp.Parent, lp.Unchanged, tc.lineage, tc.parent, tc.unchanged)
			}
		})
	}
}

func TestChainFollowsNonSuccessorLinks(t *testing.T) {
	t.Parallel()
	e := func(gen, parent uint64, l capsule.Lineage) capslog.Entry {
		return capslog.Entry{Gen: gen, Parent: parent, Lineage: string(l)}
	}
	got := chain([]capslog.Entry{
		e(1, 0, capsule.LineageFresh), e(2, 1, capsule.LineageSuccessor), e(4, 2, capsule.LineagePartial),
		e(6, 4, capsule.LineageDiverged), {Gen: 7, Blob: true},
	})
	var gens []uint64
	for _, en := range got {
		gens = append(gens, en.Gen)
	}
	if fmt.Sprint(gens) != "[6 4 2]" {
		t.Fatalf("chain %v (gaps allowed, blobs ignored)", gens)
	}
	if chain(nil) != nil {
		t.Fatal("empty chain")
	}
	if c := chain([]capslog.Entry{e(5, 5, capsule.LineageDiverged)}); len(c) != 1 {
		t.Fatalf("self loop %v", c)
	}
}

func TestConflictNames(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 21, 9, 5, 0, 0, time.UTC)
	stamp := at.UTC().Format("20060102-1504") // conflictName stamps the UTC minute of at
	for _, tc := range []struct{ got, want string }{
		{conflictName("projects/p/s.jsonl", conflictRestored, at, 0), "projects/p/s.jsonl.precinto-restored"},
		{conflictName("projects/p/s.jsonl", conflictRestored, at, 2), "projects/p/s.jsonl.precinto-restored.2"},
		{conflictName("docs/notes.md", conflictNote, at, 0), "docs/notes.conflict-" + stamp + ".md"},
		{conflictName("notes.md", conflictNote, at, 1), "notes.conflict-" + stamp + ".1.md"},
		{genConflictName("projects/p/s.jsonl", 3), "projects/p/s.precinto-g3.jsonl"},
		{genConflictName("a/.hidden", 2), "a/.hidden.precinto-g2"},
		{originalOf("docs/notes.conflict-" + stamp + ".md"), "docs/notes.md"},
		{originalOf("projects/p/s.jsonl.precinto-restored.1"), "projects/p/s.jsonl"},
		{originalOf("projects/p/s.precinto-g3.jsonl"), "projects/p/s.jsonl"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
	for _, rel := range []string{"a.precinto-restored", "b.conflict-20261121-0905.md", "c.precinto-g12.txt"} {
		if !isConflictCopy(rel) {
			t.Errorf("%s not recognised", rel)
		}
	}
	if isConflictCopy("projects/p/s.jsonl") {
		t.Error("ordinary file taken for a conflict copy")
	}
}

func TestUnionAndMergeHelpers(t *testing.T) {
	t.Parallel()
	got := unionLines([]byte("a\nb\nc"), []byte("b\nx\n"))
	if len(got) != 2 || string(got[0]) != "a" || string(got[1]) != "c" {
		t.Fatalf("union %q", got)
	}
	if completePrefix([]byte("a\nb")) != 2 || completePrefix([]byte("ab")) != 0 {
		t.Fatal("completePrefix")
	}
	if !strings.HasPrefix(failDetail(ErrNoSpace), codeNoSpace+": ") {
		t.Fatal("failDetail")
	}
}

// keyGuard never wipes a key under a reader and refuses keys afterwards.
func TestKeyGuard(t *testing.T) {
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	en := te.logged(u.Key)[0]
	fk, err := te.keys.FileKeys(tctx(t), []string{en.Path}, "restore")
	mustNoErr(t, err)
	kg := &keyGuard{}
	kg.add(fk)
	if !kg.has(en.Path) || kg.has("other") {
		t.Fatal("has")
	}
	done := make(chan struct{})
	mustNoErr(t, kg.with(en.Path, func(key []byte) error {
		go func() { kg.destroy(); close(done) }()
		time.Sleep(20 * time.Millisecond)
		select {
		case <-done:
			t.Error("destroyed under a reader")
		default:
		}
		if len(key) != 16 {
			t.Errorf("key length %d", len(key))
		}
		return nil
	}))
	<-done
	if err := kg.with(en.Path, func([]byte) error { return nil }); err == nil {
		t.Fatal("key usable after destroy")
	}
	if !te.keys.allDestroyed() {
		t.Fatal("underlying keys not destroyed")
	}
}
