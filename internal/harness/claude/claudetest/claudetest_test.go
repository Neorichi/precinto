package claudetest_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/claude/claudetest"
)

const (
	testSID  = "11111111-2222-3333-4444-555555555555"
	otherSID = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	marker   = "CLAUDETEST-MARKER-7f3a"
)

var modTime = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// fixture returns a layout under a fresh temp dir and a session whose cwd
// (recorded only, never created) lies in that temp dir too.
func fixture(t *testing.T) (dir string, l *claudetest.Layout, s claudetest.Session) {
	t.Helper()
	dir = t.TempDir()
	l = claudetest.New(t, filepath.Join(dir, "fake"))
	cwd := filepath.Join(dir, "home", "work", "acme")
	s = claudetest.Session{
		SID:       testSID,
		Cwd:       cwd,
		Lines:     16,
		Subagents: 2,
		Marker:    marker,
		MDWrites:  []string{filepath.Join(cwd, "docs", "notes.md"), filepath.Join(cwd, "src", "main.go")},
		PlanSlug:  "quiet-amber-river",
		ModTime:   modTime,
	}
	return dir, l, s
}

func TestNewCreatesTheSkeleton(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := claudetest.New(t, dir)
	want := &claudetest.Layout{
		ConfigDir: filepath.Join(dir, "claude"),
		TmpDir:    filepath.Join(dir, "claude-tmp"),
		CacheDir:  filepath.Join(dir, "cache", "claude-cli-nodejs"),
	}
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("New = %+v, want %+v (docs/TESTPLAN.md §2 names)", l, want)
	}
	for _, d := range []string{l.ConfigDir, filepath.Join(l.ConfigDir, "projects"), filepath.Join(l.ConfigDir, "sessions"), l.TmpDir, l.CacheDir} {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s is not a directory: %v", d, err)
		}
	}
	fi, err := os.Stat(l.TmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("TmpDir mode %v, want 0700 (SPEC §7.0)", fi.Mode().Perm())
	}
	// Idempotent on an existing skeleton, and it tightens a loose $TMP.
	if err := os.Chmod(l.TmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if again := claudetest.New(t, dir); !reflect.DeepEqual(again, want) {
		t.Fatalf("second New = %+v", again)
	}
	if fi, _ := os.Stat(l.TmpDir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("TmpDir mode %v after New, want 0700", fi.Mode().Perm())
	}
	if files := regularFiles(t, dir); len(files) != 0 {
		t.Fatalf("New wrote files: %v", files)
	}
}

func TestNewRejectsRelativeDirectories(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"", "relative/dir", "."} {
		msg := expectFatal(t, func(tb testing.TB) { claudetest.New(tb, dir) })
		if !strings.Contains(msg, "absolute") {
			t.Errorf("New(%q) failed with %q", dir, msg)
		}
	}
}

func TestWriteSessionLayoutMatchesSpec(t *testing.T) {
	t.Parallel()
	dir, l, s := fixture(t)
	paths := l.WriteSession(t, s)
	root := filepath.Join(dir, "fake")
	rawSlug := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, s.Cwd)
	slug := regexp.QuoteMeta(rawSlug)
	sid := regexp.QuoteMeta(s.SID)
	plan := regexp.QuoteMeta(s.PlanSlug)
	// Every file of the layout (SPEC §7.1.1–§7.1.4, §11.2): pattern → count.
	layout := []struct {
		re      string
		n       int
		session bool // part of the claude-session unit (sid rule)
	}{
		{`claude/projects/` + slug + `/` + sid + `\.jsonl`, 1, true},
		{`claude/projects/` + slug + `/` + sid + `/subagents/agent-[0-9a-f]{8}\.jsonl`, 2, true},
		{`claude/projects/` + slug + `/` + sid + `/subagents/agent-[0-9a-f]{8}\.meta\.json`, 2, true},
		{`claude/projects/` + slug + `/` + sid + `/tool-results/toolu_[0-9a-f]{24}\.txt`, 1, true},
		{`claude/file-history/` + sid + `/[0-9a-f]{16}@v1`, 1, true},
		{`claude/session-env/` + sid + `/sessionstart-hook-0\.sh`, 1, true},
		{`claude/tasks/` + sid + `/1\.json`, 1, true},
		{`claude/todos/` + sid + `-agent-` + sid + `\.json`, 1, true},
		{`claude-tmp/` + slug + `/` + sid + `/scratchpad/notes\.txt`, 1, true},
		{`claude-tmp/` + slug + `/` + sid + `/tasks/b[0-9a-f]{8}\.output`, 1, true},
		{`claude/projects/` + slug + `/memory/MEMORY\.md`, 1, false},
		{`claude/plans/` + plan + `\.md`, 1, false},
		{`claude/plans/` + plan + `-agent-[0-9a-f]{8}\.md`, 1, false},
		// Named after the session's first record, 30 s before its last (ModTime).
		{`cache/claude-cli-nodejs/` + slug + `/mcp-logs-claudetest/` + regexp.QuoteMeta(modTime.Add(-30*time.Second).Format("2006-01-02T15-04-05-000Z")) + `\.jsonl`, 1, false},
	}
	counts := make([]int, len(layout))
	seen := map[string]bool{}
	for i, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("path %s is outside the layout", p)
		}
		rel = filepath.ToSlash(rel)
		if seen[rel] {
			t.Fatalf("path %s returned twice", rel)
		}
		seen[rel] = true
		matched := false
		for j, e := range layout {
			if regexp.MustCompile(`^` + e.re + `$`).MatchString(rel) {
				counts[j]++
				matched = true
				if got := sessionRule(rel, s.SID); got != e.session {
					t.Errorf("%s: sid rule = %v, want %v", rel, got, e.session)
				}
			}
		}
		if !matched {
			t.Errorf("unexpected path %s", rel)
		}
		if i == 0 && !strings.HasSuffix(rel, s.SID+".jsonl") {
			t.Errorf("first path %s is not the transcript", rel)
		}
	}
	for j, e := range layout {
		if counts[j] != e.n {
			t.Errorf("%d paths match %s, want %d", counts[j], e.re, e.n)
		}
	}
	// Nothing else was written, and every returned file holds the marker in
	// its content and never in its name; mtimes are ModTime; files 0600.
	if got := regularFiles(t, root); len(got) != len(paths) {
		t.Errorf("layout holds %d files, WriteSession returned %d: %v", len(got), len(paths), got)
	}
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: not a regular file (%v)", p, err)
		}
		if !bytes.Contains(readFile(t, p), []byte(marker)) {
			t.Errorf("%s does not contain the marker", p)
		}
		if strings.Contains(p, marker) {
			t.Errorf("%s: the marker leaked into a file name", p)
		}
		if !fi.ModTime().Equal(modTime) {
			t.Errorf("%s: mtime %v, want %v", p, fi.ModTime(), modTime)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600", p, fi.Mode().Perm())
		}
	}
	// The child-notes directory Claude creates empty.
	started := filepath.Join(l.TmpDir, rawSlug, s.SID, "started")
	if fi, err := os.Stat(started); err != nil || !fi.IsDir() {
		t.Errorf("missing %s: %v", started, err)
	}
	// MDWrites targets and the cwd are recorded only, never created.
	for _, p := range append([]string{s.Cwd}, s.MDWrites...) {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s was created (err=%v)", p, err)
		}
	}
}

func TestWriteSessionTranscriptRecords(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	paths := l.WriteSession(t, s)
	tx := paths[0]
	raw := readFile(t, tx)
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("transcript does not end with a newline")
	}
	recs := records(t, tx)
	if len(recs) != s.Lines {
		t.Fatalf("%d records, want Lines=%d", len(recs), s.Lines)
	}
	conv := conversation(recs)
	if str(conv[0], "type") != "user" || conv[0]["parentUuid"] != nil {
		t.Fatalf("first record %v: want a user prompt with a null parentUuid", conv[0])
	}
	if _, ok := conv[0]["parentUuid"]; !ok {
		t.Fatal("first record lacks the parentUuid key")
	}
	seen := map[string]bool{}
	var last time.Time
	for i, r := range conv {
		u := str(r, "uuid")
		if !fixtureUUIDRE.MatchString(u) || seen[u] {
			t.Fatalf("record %d uuid %q is not a fresh fixture uuid", i, u)
		}
		seen[u] = true
		if i > 0 && str(r, "parentUuid") != str(conv[i-1], "uuid") {
			t.Errorf("record %d parentUuid %q, want %q (chain)", i, str(r, "parentUuid"), str(conv[i-1], "uuid"))
		}
		if str(r, "cwd") != s.Cwd || str(r, "sessionId") != s.SID || str(r, "slug") != s.PlanSlug {
			t.Errorf("record %d: cwd/sessionId/slug = %q/%q/%q", i, str(r, "cwd"), str(r, "sessionId"), str(r, "slug"))
		}
		if str(r, "version") == "" || r["isSidechain"] != false {
			t.Errorf("record %d: version %q isSidechain %v", i, str(r, "version"), r["isSidechain"])
		}
		at, err := time.Parse(time.RFC3339Nano, str(r, "timestamp"))
		if err != nil || !at.After(last) || at.After(modTime) {
			t.Errorf("record %d timestamp %q not increasing up to ModTime", i, str(r, "timestamp"))
		}
		last = at
	}
	types := map[string]int{}
	for _, r := range recs {
		types[str(r, "type")]++
	}
	for _, typ := range []string{"user", "assistant", "ai-title", "last-prompt", "file-history-snapshot"} {
		if types[typ] == 0 {
			t.Errorf("no %s record (types %v)", typ, types)
		}
	}
	if len(conv) != s.Lines-types["ai-title"]-types["last-prompt"]-types["file-history-snapshot"] {
		t.Errorf("metadata records carry uuids")
	}
	// Write tool_uses name the MDWrites paths in order, with the marker in
	// their input; the Edit names a non-Markdown file.
	var writes, edits []string
	for _, u := range toolUses(recs) {
		in, _ := u["input"].(map[string]any)
		switch str(u, "name") {
		case "Write":
			writes = append(writes, str(in, "file_path"))
			if !strings.Contains(str(in, "content"), marker) {
				t.Errorf("Write input lacks the marker")
			}
		case "Edit":
			edits = append(edits, str(in, "file_path"))
		case "Bash":
			if !strings.Contains(str(in, "command"), marker) {
				t.Errorf("Bash input lacks the marker")
			}
		}
	}
	if !reflect.DeepEqual(writes, s.MDWrites) {
		t.Errorf("Write paths %v, want %v", writes, s.MDWrites)
	}
	if len(edits) != 1 || strings.HasSuffix(edits[0], ".md") || !strings.HasPrefix(edits[0], s.Cwd) {
		t.Errorf("Edit paths %v", edits)
	}
	for _, r := range recs {
		switch str(r, "type") {
		case "ai-title":
			if !strings.Contains(str(r, "aiTitle"), marker) || str(r, "sessionId") != s.SID {
				t.Errorf("ai-title %v", r)
			}
		case "last-prompt":
			if !strings.Contains(str(r, "lastPrompt"), marker) {
				t.Errorf("last-prompt %v", r)
			}
		case "file-history-snapshot":
			snap, _ := r["snapshot"].(map[string]any)
			backups, _ := snap["trackedFileBackups"].(map[string]any)
			if len(backups) != 1 {
				t.Fatalf("snapshot backups %v", backups)
			}
			for path, b := range backups {
				name := str(b.(map[string]any), "backupFileName")
				if path != edits[0] {
					t.Errorf("snapshot tracks %s, want the edited file %s", path, edits[0])
				}
				if _, err := os.Stat(filepath.Join(l.ConfigDir, "file-history", s.SID, name)); err != nil {
					t.Errorf("snapshot backup %s: %v", name, err)
				}
			}
		}
	}
	// The spilled Bash output names its tool-results file.
	var spilled string
	for _, p := range paths {
		if strings.Contains(p, string(filepath.Separator)+"tool-results"+string(filepath.Separator)) {
			spilled = p
		}
	}
	if spilled == "" || !bytes.Contains(raw, []byte(spilled)) {
		t.Errorf("transcript does not reference the tool-results file %q", spilled)
	}
	// The prompt text holds the marker.
	if !strings.Contains(str(conv[0]["message"].(map[string]any), "content"), marker) {
		t.Error("first prompt lacks the marker")
	}
}

func TestWriteSessionLongTranscript(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	s.Lines, s.Subagents = 2001, 0
	recs := records(t, l.WriteSession(t, s)[0])
	if len(recs) != s.Lines {
		t.Fatalf("%d records, want %d", len(recs), s.Lines)
	}
	conv := conversation(recs)
	for i := 1; i < len(conv); i++ {
		if str(conv[i], "parentUuid") != str(conv[i-1], "uuid") {
			t.Fatalf("chain broken at conversation record %d", i)
		}
	}
	// After the scripted head the session alternates prompts and answers,
	// all marked.
	tail := recs[len(recs)-6:]
	for i, r := range tail {
		typ := str(r, "type")
		if typ != "user" && typ != "assistant" || i > 0 && typ == str(tail[i-1], "type") {
			t.Fatalf("tail record %d is %s after %s", i, typ, str(tail[max(i-1, 0)], "type"))
		}
		if b, _ := json.Marshal(r["message"]); !bytes.Contains(b, []byte(marker)) {
			t.Fatalf("tail record %d lacks the marker", i)
		}
	}
}

func TestWriteSessionSubagents(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	paths := l.WriteSession(t, s)
	var agents []string
	for _, p := range paths {
		if strings.Contains(p, "/subagents/") && strings.HasSuffix(p, ".jsonl") {
			agents = append(agents, p)
		}
	}
	if len(agents) != s.Subagents {
		t.Fatalf("%d subagent transcripts, want %d", len(agents), s.Subagents)
	}
	main := uuidSet(t, paths[0])
	for _, a := range agents {
		recs := records(t, a)
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(a), "agent-"), ".jsonl")
		if recs[0]["parentUuid"] != nil || str(recs[0], "type") != "user" {
			t.Errorf("%s: first record %v", a, recs[0])
		}
		for i, r := range recs {
			if r["isSidechain"] != true || str(r, "agentId") != id || str(r, "sessionId") != s.SID || str(r, "cwd") != s.Cwd {
				t.Errorf("%s record %d: %v", a, i, r)
			}
			if i > 0 && str(r, "parentUuid") != str(recs[i-1], "uuid") {
				t.Errorf("%s record %d breaks the chain", a, i)
			}
			if main[str(r, "uuid")] {
				t.Errorf("%s reuses a uuid of another transcript", a)
			}
		}
		var meta map[string]any
		if err := json.Unmarshal(readFile(t, strings.TrimSuffix(a, ".jsonl")+".meta.json"), &meta); err != nil || str(meta, "agentType") == "" {
			t.Errorf("%s.meta.json: %v %v", a, meta, err)
		}
	}
}

func TestWriteSessionNoNewline(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	s.Lines, s.MDWrites, s.NoNewline = 3, s.MDWrites[:1], true
	tx := l.WriteSession(t, s)[0]
	raw := readFile(t, tx)
	if bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("NoNewline transcript ends with a newline")
	}
	lines := bytes.Split(raw, []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3", len(lines))
	}
	for i, line := range lines {
		if !json.Valid(line) {
			t.Fatalf("line %d is not a complete record", i+1)
		}
	}
	// The same session with a newline differs only by that byte.
	_, l2, s2 := fixture(t)
	s2.Cwd, s2.MDWrites, s2.Lines = s.Cwd, s.MDWrites, 3
	if full := readFile(t, l2.WriteSession(t, s2)[0]); !bytes.Equal(append(raw, '\n'), full) {
		t.Fatal("NoNewline changed more than the trailing newline")
	}
}

func TestWriteSessionDefaultsAndDeterminism(t *testing.T) {
	t.Parallel()
	dir, l, s := fixture(t)
	s.Lines = 0 // default record count
	s.MDWrites = nil
	p1 := l.WriteSession(t, s)
	if n := len(jsonlLines(t, p1[0])); n != 12 {
		t.Fatalf("default transcript has %d records, want 12", n)
	}
	contents := map[string][]byte{}
	for _, p := range p1 {
		contents[p] = readFile(t, p)
	}
	// With ModTime fixed, rewriting the same Session at the same place (a
	// sealed session written again) yields byte-identical files.
	root := filepath.Join(dir, "fake")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	l = claudetest.New(t, root)
	p2 := l.WriteSession(t, s)
	if !reflect.DeepEqual(p1, p2) {
		t.Fatalf("paths differ:\n%v\n%v", p1, p2)
	}
	for _, p := range p2 {
		if !bytes.Equal(contents[p], readFile(t, p)) {
			t.Fatalf("%s differs on rewrite", p)
		}
	}
	// Without a marker no content is marked, and the paths are the same.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	l = claudetest.New(t, root)
	s.Marker = ""
	p3 := l.WriteSession(t, s)
	if !reflect.DeepEqual(p1, p3) {
		t.Fatalf("paths depend on the marker:\n%v\n%v", p1, p3)
	}
	for _, p := range p3 {
		if bytes.Contains(readFile(t, p), []byte(marker)) {
			t.Errorf("%s holds a marker that was not given", p)
		}
	}
}

func TestWriteSessionSlugs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := claudetest.New(t, dir)
	cases := []struct {
		name, cwd, slug, want string
	}{
		{"punctuation", "/srv/my proj/v1.2_x", "", "-srv-my-proj-v1-2-x"},
		{"unicode", "/srv/café/\U0001F600", "", "-srv-caf--" + "--"},
		{"explicit", "/srv/anything", "renamed-project", "renamed-project"},
	}
	for i, c := range cases {
		sid := []string{testSID, otherSID, "77777777-8888-4999-aaaa-bbbbbbbbbbbb"}[i]
		paths := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: c.cwd, Slug: c.slug})
		want := filepath.Join(l.ConfigDir, "projects", c.want, sid+".jsonl")
		if paths[0] != want {
			t.Errorf("%s: transcript %s, want %s", c.name, paths[0], want)
		}
		// $TMP/<P> and $CACHE/<P> use the same project directory name.
		for _, base := range []string{l.TmpDir, l.CacheDir} {
			if _, err := os.Stat(filepath.Join(base, c.want)); err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
		}
	}
	long := "/" + strings.Repeat("deep/", 50)
	p := l.WriteSession(t, claudetest.Session{SID: "88888888-9999-4aaa-bbbb-cccccccccccc", Cwd: long})[0]
	slug := filepath.Base(filepath.Dir(p))
	if len(slug) != 209 || !strings.HasPrefix(slug, "-deep-deep-") || !regexp.MustCompile(`-[0-9a-f]{8}$`).MatchString(slug) {
		t.Errorf("long cwd slug %q (len %d), want 200 sanitized chars + '-' + 8 hex", slug, len(slug))
	}
}

func TestWriteSessionSharedFilesAreWrittenOnce(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	first := l.WriteSession(t, s)
	second := l.WriteSession(t, claudetest.Session{SID: otherSID, Cwd: s.Cwd, Subagents: 1, PlanSlug: s.PlanSlug, Marker: "SECOND-MARKER"})
	for _, p := range second {
		if strings.HasSuffix(p, "MEMORY.md") || strings.HasSuffix(p, s.PlanSlug+".md") {
			t.Errorf("second session re-created shared %s", p)
		}
	}
	var mcp []string
	for _, p := range append(first, second...) {
		if strings.Contains(p, "mcp-logs-") {
			mcp = append(mcp, p)
		}
		if strings.HasSuffix(p, "MEMORY.md") && bytes.Contains(readFile(t, p), []byte("SECOND-MARKER")) {
			t.Errorf("memory was overwritten")
		}
	}
	if len(mcp) != 2 || mcp[0] == mcp[1] {
		t.Errorf("MCP logs %v: want one per session", mcp)
	}
}

func TestWriteSessionRejectsBadInput(t *testing.T) {
	t.Parallel()
	dir, l, s := fixture(t)
	mutate := func(f func(*claudetest.Session)) claudetest.Session { c := s; f(&c); return c }
	cases := map[string]claudetest.Session{
		"empty sid":        mutate(func(c *claudetest.Session) { c.SID = "" }),
		"sid with slash":   mutate(func(c *claudetest.Session) { c.SID = "../escape" }),
		"dot-dot sid":      mutate(func(c *claudetest.Session) { c.SID = ".." }),
		"relative cwd":     mutate(func(c *claudetest.Session) { c.Cwd = "work/acme" }),
		"slug with slash":  mutate(func(c *claudetest.Session) { c.Slug = "a/b" }),
		"dot-dot plan":     mutate(func(c *claudetest.Session) { c.PlanSlug = ".." }),
		"too few lines":    mutate(func(c *claudetest.Session) { c.Lines = 4 }),
		"negative agents":  mutate(func(c *claudetest.Session) { c.Subagents = -1 }),
		"quote in marker":  mutate(func(c *claudetest.Session) { c.Marker = `a"b` }),
		"newline marker":   mutate(func(c *claudetest.Session) { c.Marker = "a\nb" }),
		"empty md write":   mutate(func(c *claudetest.Session) { c.MDWrites = []string{""} }),
		"apostrophe in mk": mutate(func(c *claudetest.Session) { c.Marker = "it's" }),
	}
	for name, c := range cases {
		expectFatal(t, func(tb testing.TB) { l.WriteSession(tb, c) })
		if files := regularFiles(t, filepath.Join(dir, "fake")); len(files) != 0 {
			t.Fatalf("%s: files written before failing: %v", name, files)
		}
	}
	expectFatal(t, func(tb testing.TB) { (*claudetest.Layout)(nil).WriteSession(tb, s) })
	expectFatal(t, func(tb testing.TB) {
		(&claudetest.Layout{ConfigDir: "rel", TmpDir: l.TmpDir, CacheDir: l.CacheDir}).WriteSession(tb, s)
	})
	expectFatal(t, func(tb testing.TB) {
		(&claudetest.Layout{ConfigDir: l.ConfigDir, TmpDir: l.TmpDir}).WriteSession(tb, s)
	})
	// Fixtures never clobber: a second write of the same session fails and
	// leaves the first transcript as it was.
	tx := l.WriteSession(t, s)[0]
	before := readFile(t, tx)
	msg := expectFatal(t, func(tb testing.TB) { l.WriteSession(tb, s) })
	if !strings.Contains(msg, "exists") || !bytes.Equal(before, readFile(t, tx)) {
		t.Fatalf("rewrite: %q", msg)
	}
}

func TestWriteSessionRefusesSymlinkedDirectories(t *testing.T) {
	t.Parallel()
	dir, l, s := fixture(t)
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(l.ConfigDir, "file-history")); err != nil {
		t.Fatal(err)
	}
	msg := expectFatal(t, func(tb testing.TB) { l.WriteSession(tb, s) })
	if !strings.Contains(msg, "symlink") {
		t.Fatalf("failure %q", msg)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote through the symlink: %v", entries)
	}
}

func TestAppendFragmentLinksIntoTheOriginal(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	tx := l.WriteSession(t, s)[0]
	orig := records(t, tx)
	conv := conversation(orig)
	lastUUID := str(conv[len(conv)-1], "uuid")
	moved := tx + ".moved"
	if err := os.Rename(tx, moved); err != nil {
		t.Fatal(err)
	}

	if got := l.AppendFragment(t, s, 3); got != tx {
		t.Fatalf("AppendFragment = %s, want %s", got, tx)
	}
	raw := readFile(t, tx)
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("fragment lacks its trailing newline")
	}
	frag := records(t, tx)
	if len(frag) != 3 {
		t.Fatalf("%d fragment records, want 3", len(frag))
	}
	if str(frag[0], "parentUuid") != lastUUID {
		t.Fatalf("first parentUuid %q, want the original's last uuid %q (E8)", str(frag[0], "parentUuid"), lastUUID)
	}
	origSet := uuidSet(t, moved)
	for i, r := range frag {
		if origSet[str(r, "uuid")] || !fixtureUUIDRE.MatchString(str(r, "uuid")) {
			t.Errorf("fragment record %d uuid %q not disjoint/fixture", i, str(r, "uuid"))
		}
		if i > 0 && str(r, "parentUuid") != str(frag[i-1], "uuid") {
			t.Errorf("fragment record %d breaks the chain", i)
		}
		if str(r, "sessionId") != s.SID || str(r, "cwd") != s.Cwd {
			t.Errorf("fragment record %d: %v", i, r)
		}
	}
	if !bytes.Contains(raw, []byte(marker)) {
		t.Error("fragment lacks the marker")
	}

	// Claude appends to an existing file: the next fragment continues the
	// chain from the file's last record, with fresh uuids.
	l.AppendFragment(t, s, 2)
	all := records(t, tx)
	if len(all) != 5 || str(all[3], "parentUuid") != str(all[2], "uuid") {
		t.Fatalf("second fragment does not continue the chain: %d records", len(all))
	}
	if uuids := uuidSet(t, tx); len(uuids) != 5 {
		t.Fatalf("fragment uuids repeat: %d unique of 5", len(uuids))
	}

	expectFatal(t, func(tb testing.TB) { l.AppendFragment(tb, s, 0) })
}

func TestAppendFragmentWithoutAnOriginalOnDisk(t *testing.T) {
	t.Parallel()
	// The original never existed in this layout (it was sealed elsewhere):
	// the parent is recomputed from the Session alone.
	_, l, s := fixture(t)
	_, l2, _ := fixture(t)
	want := conversation(records(t, l2.WriteSession(t, s)[0]))
	frag := records(t, l.AppendFragment(t, s, 1))
	if str(frag[0], "parentUuid") != str(want[len(want)-1], "uuid") {
		t.Fatalf("parentUuid %q, want %q", str(frag[0], "parentUuid"), str(want[len(want)-1], "uuid"))
	}
}

func TestWriteRegistryValidAndTruncated(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	before := time.Now().Add(-time.Second).UnixMilli()
	p := l.WriteRegistry(t, 4242, s.SID, s.Cwd, "busy", true)
	if p != filepath.Join(l.ConfigDir, "sessions", "4242.json") {
		t.Fatalf("path %s", p)
	}
	var reg map[string]any
	if err := json.Unmarshal(readFile(t, p), &reg); err != nil {
		t.Fatal(err)
	}
	if reg["pid"] != float64(4242) || str(reg, "sessionId") != s.SID || str(reg, "cwd") != s.Cwd || str(reg, "status") != "busy" ||
		str(reg, "kind") != "interactive" || str(reg, "entrypoint") != "cli" || str(reg, "procStart") == "" {
		t.Fatalf("registry %v", reg)
	}
	if at, _ := reg["startedAt"].(float64); int64(at) < before || int64(at) > time.Now().UnixMilli() {
		t.Fatalf("startedAt %v is not now in Unix ms", reg["startedAt"])
	}
	// The .key sibling (written first by Claude) exists once per pid.
	keys, _ := filepath.Glob(filepath.Join(l.ConfigDir, "sessions", "4242.*.key"))
	if len(keys) != 1 || !regexp.MustCompile(`/4242\.[0-9a-f]{64}\.key$`).MatchString(keys[0]) || len(readFile(t, keys[0])) != 108 {
		t.Fatalf("key files %v", keys)
	}

	// An entry with no status yet omits the key.
	l.WriteRegistry(t, 4242, s.SID, s.Cwd, "", true)
	reg = nil
	if err := json.Unmarshal(readFile(t, p), &reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg["status"]; ok {
		t.Fatalf("status present: %v", reg)
	}

	// valid=false replaces it with a half-written entry that never parses.
	if got := l.WriteRegistry(t, 4242, s.SID, s.Cwd, "idle", false); got != p {
		t.Fatalf("path %s", got)
	}
	half := readFile(t, p)
	if json.Valid(half) || len(half) == 0 || !bytes.HasPrefix(half, []byte(`{"pid":4242,`)) {
		t.Fatalf("truncated registry %q", half)
	}
	if keys, _ := filepath.Glob(filepath.Join(l.ConfigDir, "sessions", "4242.*.key")); len(keys) != 1 {
		t.Fatalf("key files %v", keys)
	}
	if entries, _ := os.ReadDir(filepath.Join(l.ConfigDir, "sessions")); len(entries) != 2 {
		t.Fatalf("sessions/ holds %d entries (temporaries left?)", len(entries))
	}
	for _, pid := range []int{0, -1} {
		expectFatal(t, func(tb testing.TB) { l.WriteRegistry(tb, pid, s.SID, s.Cwd, "idle", true) })
	}
}

func TestWriteHistoryLinesAndPasteCache(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	hist := filepath.Join(l.ConfigDir, "history.jsonl")
	l.WriteHistory(t, s.Cwd, s.SID, 0, marker)
	if _, err := os.Lstat(hist); !os.IsNotExist(err) {
		t.Fatalf("n=0 created history.jsonl: %v", err)
	}
	l.WriteHistory(t, s.Cwd, s.SID, 3, marker)
	other := filepath.Join(filepath.Dir(s.Cwd), "outside")
	l.WriteHistory(t, other, otherSID, 2, marker)   // same pastes as above
	l.WriteHistory(t, other, "", 1, "OTHER-MARKER") // a legacy line without sessionId
	recs := records(t, hist)
	if len(recs) != 6 {
		t.Fatalf("%d history lines, want 6", len(recs))
	}
	var last float64
	refs := map[string]int{}
	for i, r := range recs {
		ts, _ := r["timestamp"].(float64)
		if ts <= last {
			t.Errorf("line %d timestamp %v not increasing", i, ts)
		}
		last = ts
		if !strings.Contains(str(r, "display"), "MARKER") {
			t.Errorf("line %d display lacks the marker", i)
		}
		pasted, ok := r["pastedContents"].(map[string]any)
		if !ok {
			t.Fatalf("line %d pastedContents %v", i, r["pastedContents"])
		}
		for _, v := range pasted {
			hash := str(v.(map[string]any), "contentHash")
			refs[hash]++
			content := readFile(t, filepath.Join(l.ConfigDir, "paste-cache", hash+".txt"))
			if !bytes.Contains(content, []byte("MARKER")) {
				t.Errorf("paste %s lacks the marker", hash)
			}
		}
	}
	wantProject := []string{s.Cwd, s.Cwd, s.Cwd, other, other, other}
	wantSID := []string{s.SID, s.SID, s.SID, otherSID, otherSID, ""}
	for i, r := range recs {
		if str(r, "project") != wantProject[i] || str(r, "sessionId") != wantSID[i] {
			t.Errorf("line %d project/sessionId %q/%q", i, str(r, "project"), str(r, "sessionId"))
		}
	}
	if _, ok := recs[5]["sessionId"]; ok {
		t.Error("an empty sid was written")
	}
	// Lines 0 and 2 of the first call paste; line 0 of the second call
	// pastes the same text (shared entry); the other marker pastes its own.
	entries, _ := os.ReadDir(filepath.Join(l.ConfigDir, "paste-cache"))
	if len(entries) != 3 || len(refs) != 3 {
		t.Fatalf("paste entries %d, referenced %v", len(entries), refs)
	}
	shared := 0
	for _, n := range refs {
		if n == 2 {
			shared++
		}
	}
	if shared != 1 {
		t.Fatalf("want exactly one paste shared by two projects: %v", refs)
	}
	expectFatal(t, func(tb testing.TB) { l.WriteHistory(tb, s.Cwd, s.SID, -1, marker) })
	expectFatal(t, func(tb testing.TB) { l.WriteHistory(tb, s.Cwd, s.SID, 1, `x"y`) })
}

func TestWriteJob(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	l.WriteJob(t, "job-7", s.SID, "running")
	p := filepath.Join(l.ConfigDir, "jobs", "job-7", "state.json")
	var job map[string]any
	if err := json.Unmarshal(readFile(t, p), &job); err != nil {
		t.Fatal(err)
	}
	if str(job, "id") != "job-7" || str(job, "sessionId") != s.SID || str(job, "state") != "running" {
		t.Fatalf("job %v", job)
	}
	l.WriteJob(t, "job-7", s.SID, "stopped") // jobs are rewritten as they change
	job = nil
	if err := json.Unmarshal(readFile(t, p), &job); err != nil || str(job, "state") != "stopped" {
		t.Fatalf("job %v %v", job, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Fatalf("jobs/job-7 holds %d entries", len(entries))
	}
	for _, id := range []string{"", "..", "a/b"} {
		expectFatal(t, func(tb testing.TB) { l.WriteJob(tb, id, s.SID, "running") })
	}
}

// waitFor polls cond for up to 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func lineCount(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return bytes.Count(b, []byte("\n"))
}

func TestAppenderSimulatesClaudesWriter(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	s.Lines, s.MDWrites = 4, nil
	tx := l.WriteSession(t, s)[0]
	conv := conversation(records(t, tx))
	lastUUID := str(conv[len(conv)-1], "uuid")

	a := claudetest.StartAppender(t, tx, 2*time.Millisecond)
	// The first record is appended before StartAppender returns, chained to
	// the transcript's last uuid.
	recs := records(t, tx)
	if len(recs) != 5 || str(recs[4], "parentUuid") != lastUUID || str(recs[4], "sessionId") != s.SID || str(recs[4], "cwd") != s.Cwd {
		t.Fatalf("first appended record %v", recs[len(recs)-1])
	}
	waitFor(t, "appends", func() bool { return lineCount(tx) >= 8 })

	// Move the transcript away mid-session: the writer recreates it with a
	// fragment whose first parentUuid points into the moved part (E8).
	moved := tx + ".moved"
	if err := os.Rename(tx, moved); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the recreated transcript", func() bool { return lineCount(tx) >= 3 })
	n := a.Stop()
	if again := a.Stop(); again != n {
		t.Fatalf("second Stop = %d, want %d", again, n)
	}
	movedRecs, fragRecs := records(t, moved), records(t, tx)
	if got := len(movedRecs) - 4 + len(fragRecs); got != n {
		t.Fatalf("Stop = %d, files hold %d appended records", n, got)
	}
	movedSet := uuidSet(t, moved)
	if !movedSet[str(fragRecs[0], "parentUuid")] {
		t.Fatalf("fragment parentUuid %q is not in the moved part", str(fragRecs[0], "parentUuid"))
	}
	for i, r := range fragRecs {
		if movedSet[str(r, "uuid")] {
			t.Errorf("fragment record %d reuses uuid %s", i, str(r, "uuid"))
		}
	}
	// Writing stopped.
	size := len(readFile(t, tx))
	time.Sleep(20 * time.Millisecond)
	if len(readFile(t, tx)) != size {
		t.Fatal("the appender kept writing after Stop")
	}
}

func TestAppenderContinuesASubagentSidechain(t *testing.T) {
	t.Parallel()
	_, l, s := fixture(t)
	var agent string
	for _, p := range l.WriteSession(t, s) {
		if strings.Contains(p, "/subagents/") && strings.HasSuffix(p, ".jsonl") {
			agent = p
			break
		}
	}
	before := records(t, agent)
	a := claudetest.StartAppender(t, agent, time.Hour) // only the synchronous first record
	if n := a.Stop(); n != 1 {
		t.Fatalf("Stop = %d, want 1", n)
	}
	recs := records(t, agent)
	last, prev := recs[len(recs)-1], before[len(before)-1]
	if len(recs) != len(before)+1 || str(last, "parentUuid") != str(prev, "uuid") || last["isSidechain"] != true ||
		str(last, "agentId") != str(prev, "agentId") || str(last, "sessionId") != s.SID || str(last, "slug") != s.PlanSlug {
		t.Fatalf("appended %v after %v", last, prev)
	}
}

func TestAppenderCreatesAMissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, otherSID+".jsonl")
	a := claudetest.StartAppender(t, path, 0) // default interval
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file not created 0600: %v %v", fi, err)
	}
	waitFor(t, "a second record", func() bool { return lineCount(path) >= 2 })
	n := a.Stop()
	recs := records(t, path)
	if n != len(recs) || recs[0]["parentUuid"] != nil || str(recs[0], "sessionId") != otherSID {
		t.Fatalf("Stop=%d records=%d first=%v", n, len(recs), recs[0])
	}
	if str(recs[1], "parentUuid") != str(recs[0], "uuid") {
		t.Fatal("records do not chain")
	}

	expectFatal(t, func(tb testing.TB) { claudetest.StartAppender(tb, "relative.jsonl", time.Millisecond) })
	expectFatal(t, func(tb testing.TB) {
		claudetest.StartAppender(tb, filepath.Join(dir, "missing", "x.jsonl"), time.Millisecond)
	})
	var zero claudetest.Appender
	if zero.Stop() != 0 || (*claudetest.Appender)(nil).Stop() != 0 {
		t.Fatal("Stop of a zero or nil Appender")
	}
}

// TestHelpersStayInsideTheirDirectory runs every helper and checks that
// nothing outside the layout changed: a sibling canary, the test's working
// directory, and the paths recorded in JSON content (S13: only fixture
// paths under the test's temp dir).
func TestHelpersStayInsideTheirDirectory(t *testing.T) {
	outer := t.TempDir()
	canary := filepath.Join(outer, "canary")
	if err := os.MkdirAll(canary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(canary, "keep.txt"), []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	canaryBefore := dirListing(t, canary)
	cwdBefore := dirListing(t, ".")

	root := filepath.Join(outer, "layout")
	l := claudetest.New(t, root)
	cwd := filepath.Join(outer, "project")
	s := claudetest.Session{SID: testSID, Cwd: cwd, Subagents: 1, Marker: marker, MDWrites: []string{filepath.Join(cwd, "a.md")}, PlanSlug: "plan-x"}
	paths := l.WriteSession(t, s)
	if err := os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
	l.AppendFragment(t, s, 2)
	l.WriteRegistry(t, 100, s.SID, cwd, "idle", true)
	l.WriteRegistry(t, 101, s.SID, cwd, "busy", false)
	l.WriteHistory(t, cwd, s.SID, 4, marker)
	l.WriteJob(t, "job-1", s.SID, "running")
	a := claudetest.StartAppender(t, paths[0], time.Millisecond)
	waitFor(t, "appends", func() bool { return lineCount(paths[0]) >= 4 })
	a.Stop()

	entries, err := os.ReadDir(outer)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"canary", "layout"}) {
		t.Fatalf("outside the layout: %v (the cwd %s must never be created)", names, cwd)
	}
	if after := dirListing(t, canary); !reflect.DeepEqual(after, canaryBefore) {
		t.Fatalf("canary changed: %v", after)
	}
	if after := dirListing(t, "."); !reflect.DeepEqual(after, cwdBefore) {
		t.Fatalf("the working directory changed: %v", after)
	}
	for _, rel := range regularFiles(t, root) {
		p := filepath.Join(root, rel)
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if top != "claude" && top != "claude-tmp" && top != "cache" {
			t.Errorf("%s is outside ConfigDir/TmpDir/CacheDir", p)
		}
		if !strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, ".jsonl") {
			continue
		}
		for _, line := range bytes.Split(readFile(t, p), []byte("\n")) {
			var v any
			if json.Unmarshal(line, &v) != nil {
				continue // the truncated registry entry
			}
			var abs []string
			absoluteStrings(v, &abs)
			for _, a := range abs {
				if !strings.HasPrefix(a, outer+string(filepath.Separator)) {
					t.Errorf("%s records %q, outside the test's temp dir", p, a)
				}
			}
		}
	}
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			t.Errorf("symlink %s", p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
