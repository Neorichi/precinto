package testkit_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/testkit"
)

func TestMarker(t *testing.T) {
	format := regexp.MustCompile(`^precinto-marker-[0-9]+-[0-9a-f]{20}$`)
	seen := map[string]bool{}
	var all []string
	for i := 0; i < 1000; i++ {
		m := testkit.Marker(t)
		if !format.MatchString(m) {
			t.Fatalf("Marker = %q", m)
		}
		if seen[m] {
			t.Fatalf("Marker repeated %q", m)
		}
		seen[m] = true
		all = append(all, m)
	}
	// Markers go verbatim into JSON, shell and Markdown fixtures, and never
	// trip the hygiene check.
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"m.json": `{"prompt": "` + strings.Join(all, " ") + `"}`})
	if r := hygieneOf(t, dir); r.Failed() {
		t.Errorf("markers fail hygiene: %s", r.text())
	}
}

func TestGrepTree(t *testing.T) {
	m := testkit.Marker(t)
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"clean.txt":                      "nothing here\n",
		"state/sessions/s.jsonl":         `{"note": "` + m + `"}` + "\n",
		"logs/precinto.log":              "ok\n",
		"capsules/claude-code/k/g1.pcap": "binary " + m,
		"deep/a/capsules/x":              m,
		"notes/" + m + ".md":             "name only\n",
		"other/blob.pcap":                m,
	})
	if err := os.Symlink("/elsewhere/"+m, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	join := func(rels ...string) []string {
		var out []string
		for _, r := range rels {
			out = append(out, filepath.Join(dir, filepath.FromSlash(r)))
		}
		slices.Sort(out)
		return out
	}
	got := testkit.GrepTree(t, dir, m)
	want := join("capsules/claude-code/k/g1.pcap", "deep/a/capsules/x", "link", "notes/"+m+".md", "other/blob.pcap", "state/sessions/s.jsonl")
	if !slices.Equal(got, want) {
		t.Errorf("GrepTree =\n%q\nwant\n%q", got, want)
	}
	// A name pattern excludes that name at any depth; a path pattern only
	// that subtree; an absolute path that entry.
	got = testkit.GrepTree(t, dir, m, "capsules", "*.pcap", filepath.Join(dir, "notes"))
	if want := join("link", "state/sessions/s.jsonl"); !slices.Equal(got, want) {
		t.Errorf("with name excludes = %q, want %q", got, want)
	}
	got = testkit.GrepTree(t, dir, m, "capsules/claude-code", "state/*")
	if want := join("deep/a/capsules/x", "link", "notes/"+m+".md", "other/blob.pcap"); !slices.Equal(got, want) {
		t.Errorf("with path excludes = %q, want %q", got, want)
	}
	if got := testkit.GrepTree(t, dir, testkit.Marker(t)); len(got) != 0 {
		t.Errorf("fresh marker found in %q", got)
	}
}

func TestGrepTreeLargeFile(t *testing.T) {
	m := testkit.Marker(t)
	dir := t.TempDir()
	// The marker straddles the 1 MiB read window.
	big := bytes.Repeat([]byte("z"), 1<<20-len(m)/2)
	big = append(big, m...)
	big = append(big, bytes.Repeat([]byte("z"), 100)...)
	if err := os.WriteFile(filepath.Join(dir, "big"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := testkit.GrepTree(t, dir, m); len(got) != 1 {
		t.Errorf("marker across the window boundary: %q", got)
	}
}

func TestGrepTreeErrors(t *testing.T) {
	dir := t.TempDir()
	mustFatal(t, "empty marker", func(tb testing.TB) { testkit.GrepTree(tb, dir, "") })
	mustFatal(t, "testkit.GrepTree", func(tb testing.TB) { testkit.GrepTree(tb, filepath.Join(dir, "missing"), "m") })
	mustFatal(t, "syntax error", func(tb testing.TB) { testkit.GrepTree(tb, dir, "m", "[") })
	mustFatal(t, "matches nothing", func(tb testing.TB) { testkit.GrepTree(tb, dir, "m", "..") })
	mustFatal(t, "is not below", func(tb testing.TB) { testkit.GrepTree(tb, dir, "m", "/elsewhere") })
	mustFatal(t, "is not below", func(tb testing.TB) { testkit.GrepTree(tb, dir, "m", dir) })
	if os.Geteuid() == 0 {
		return
	}
	writeFiles(t, dir, map[string]string{"locked.txt": "x"})
	if err := os.Chmod(filepath.Join(dir, "locked.txt"), 0o000); err != nil {
		t.Fatal(err)
	}
	var hits []string
	r := record(t, func(tb testing.TB) { hits = testkit.GrepTree(tb, dir, "m") })
	if !strings.Contains(r.text(), "cannot search locked.txt") || len(hits) != 1 {
		t.Errorf("unreadable file: hits %q, output %q", hits, r.text())
	}
}
