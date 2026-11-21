package claude_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
)

const (
	sid1 = "00000000-0000-4000-8000-000000000001"
	sid2 = "00000000-0000-4000-8000-000000000002"
	sid3 = "00000000-0000-4000-8000-000000000003"
)

func layout(t *testing.T) *claudetest.Layout {
	t.Helper()
	return claudetest.New(t, t.TempDir())
}

func TestReadRegistryValidMalformedAndSiblings(t *testing.T) {
	t.Parallel()
	l := layout(t)
	if got, err := claude.ReadRegistry(l.ConfigDir); err != nil || len(got) != 0 {
		t.Fatalf("empty registry: %v %v", got, err)
	}
	started := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 101, SessionID: sid1, Cwd: "/u/work/acme", Status: "busy",
		Kind: "interactive", Entrypoint: "cli", StartedAt: started, Valid: true})
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 102, SessionID: sid2, Status: "busy", WaitingFor: "permission", Valid: true})
	l.WriteRegistry(t, 103, sid3, "/u/x", "idle", false) // half-written
	l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 104, SessionID: sid3, Valid: true})
	dir := filepath.Join(l.ConfigDir, "sessions")
	os.WriteFile(filepath.Join(dir, "105.json"), []byte(`{"pid":999,"sessionId":"`+sid1+`"}`), 0o600) // names another pid
	os.WriteFile(filepath.Join(dir, "106.json"), []byte(`{"pid":106}`), 0o600)                        // no session id
	os.WriteFile(filepath.Join(dir, "107.json"), []byte(`[1,2]`), 0o600)                              // not an object
	os.WriteFile(filepath.Join(dir, "107.sock"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "notes.json"), []byte(`{}`), 0o600)
	os.WriteFile(filepath.Join(dir, "0108.json"), []byte(`{}`), 0o600) // not a canonical pid
	os.Symlink(filepath.Join(dir, "101.json"), filepath.Join(dir, "109.json"))

	got, err := claude.ReadRegistry(l.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]claude.RegistryEntry{}
	for _, e := range got {
		byPID[e.PID] = e
		if strings.HasSuffix(e.Path, ".key") {
			t.Errorf("a .key sibling was read: %s", e.Path)
		}
	}
	if len(got) != 8 {
		t.Fatalf("entries = %d, want 8", len(got))
	}
	e := byPID[101]
	if !e.Valid || e.SessionID != sid1 || e.Cwd != "/u/work/acme" || e.Status != "busy" || e.Kind != "interactive" ||
		e.Entrypoint != "cli" || !e.StartedAt.Equal(started) || e.Mtime.IsZero() || !e.Busy() {
		t.Errorf("101 = %+v", e)
	}
	if e := byPID[102]; !e.Valid || e.WaitingFor != "permission" || e.Busy() {
		t.Errorf("102 (waiting on a permission dialog counts as idle, HA7) = %+v", e)
	}
	if e := byPID[104]; !e.Valid || !e.StartedAt.IsZero() || e.Busy() {
		t.Errorf("104 (no startedAt, no status) = %+v", e)
	}
	for _, pid := range []int{103, 105, 106, 107, 109} {
		if e := byPID[pid]; e.Valid || e.PID != pid {
			t.Errorf("%d must be invalid: %+v", pid, e)
		}
	}
	if _, ok := byPID[108]; ok {
		t.Error("0108.json was read as pid 108")
	}
	if _, err := claude.ReadRegistry("relative"); err == nil {
		t.Error("relative config dir accepted")
	}
}

func TestReadJobs(t *testing.T) {
	t.Parallel()
	l := layout(t)
	if got, err := claude.ReadJobs(l.ConfigDir); err != nil || got != nil {
		t.Fatalf("no jobs dir: %v %v", got, err)
	}
	l.WriteJob(t, "job-a", sid1, "running")
	l.WriteJob(t, "job-b", sid2, "stopped")
	os.MkdirAll(filepath.Join(l.ConfigDir, "jobs", "job-c"), 0o700) // no state.json
	os.MkdirAll(filepath.Join(l.ConfigDir, "jobs", "job-d"), 0o700)
	os.WriteFile(filepath.Join(l.ConfigDir, "jobs", "job-d", "state.json"), []byte(`{"id":"job-d","state":"running"}`), 0o600)
	got, err := claude.ReadJobs(l.ConfigDir)
	if err != nil {
		t.Fatal(err)
	}
	want := []claude.Job{
		{ID: "job-a", SessionID: sid1, State: "running", Valid: true},
		{ID: "job-b", SessionID: sid2, State: "stopped", Valid: true},
		{ID: "job-c"},
		{ID: "job-d"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadJobs = %+v\nwant %+v", got, want)
	}
}

func TestParseHistoryLine(t *testing.T) {
	t.Parallel()
	l := layout(t)
	l.WriteHistory(t, "/u/work/acme", sid1, 2, "HISTMARK")
	data, err := os.ReadFile(filepath.Join(l.ConfigDir, "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("history lines = %d", len(lines))
	}
	h := claude.ParseHistoryLine(append(append([]byte(nil), lines[0]...), '\n'))
	if !h.Valid || h.Project != "/u/work/acme" || h.SessionID != sid1 || h.Timestamp.IsZero() || len(h.PasteRefs) != 1 {
		t.Fatalf("line 0 = %+v", h)
	}
	if !strings.HasSuffix(h.PasteRefs[0], ".txt") {
		t.Errorf("paste ref %q", h.PasteRefs[0])
	}
	if _, err := os.Stat(filepath.Join(l.ConfigDir, "paste-cache", h.PasteRefs[0])); err != nil {
		t.Errorf("paste ref does not name the paste-cache entry: %v", err)
	}
	if !bytes.Equal(h.Raw, lines[0]) {
		t.Error("Raw is not the line without its newline")
	}
	lines[0][0] = 'X' // Raw is a copy
	if h.Raw[0] == 'X' {
		t.Error("Raw aliases the input")
	}
	if h := claude.ParseHistoryLine(lines[1]); !h.Valid || len(h.PasteRefs) != 0 {
		t.Errorf("line 1 = %+v", h)
	}
	for _, bad := range []string{"", "not json", "[]", `{"display":"x"}`, `{"project":""}`, `{"project":"/u"` /* torn */} {
		if h := claude.ParseHistoryLine([]byte(bad)); h.Valid {
			t.Errorf("%q parsed as valid", bad)
		}
	}
}

func TestScanTranscriptFacts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := claudetest.New(t, filepath.Join(dir, "fake"))
	cwd := filepath.Join(dir, "home", "work", "acme")
	notes := filepath.Join(cwd, "docs", "notes.md")
	readme := filepath.Join(cwd, "docs", "guide.MDX")
	at := time.Date(2026, 11, 21, 8, 30, 0, 0, time.UTC)
	s := claudetest.Session{SID: sid1, Cwd: cwd, Lines: 20, Subagents: 1, Marker: "SCANMARK",
		MDWrites: []string{notes, filepath.Join(cwd, "src", "main.go"), readme}, PlanSlug: "quiet-amber-river", ModTime: at}
	paths := l.WriteSession(t, s)
	facts, err := claude.ScanTranscript(context.Background(), paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facts.Cwds, []string{cwd}) {
		t.Errorf("Cwds = %v", facts.Cwds)
	}
	if facts.Slug != "quiet-amber-river" {
		t.Errorf("Slug = %q", facts.Slug)
	}
	if !reflect.DeepEqual(facts.MDPaths, []string{notes, readme}) {
		t.Errorf("MDPaths = %v (only Markdown)", facts.MDPaths)
	}
	if facts.Title != "SCANMARK claudetest session title" {
		t.Errorf("Title = %q (ai-title)", facts.Title)
	}
	if !facts.LastAt.Equal(at) {
		t.Errorf("LastAt = %v, want %v", facts.LastAt, at)
	}
	if facts.Uuids == 0 || facts.Uuids >= 20 || !facts.TrailingNL || len(facts.ForkRefs) != 0 || len(facts.CopiedSIDs) != 0 {
		t.Errorf("facts = %+v", facts)
	}

	// A custom title beats the ai-title; fork references and copied lines
	// of another session are found; a missing newline is reported.
	f, _ := os.OpenFile(paths[0], os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"type":"custom-title","customTitle":"  my   renamed\tsession ","sessionId":"` + sid1 + `"}` + "\n")
	f.WriteString(`{"type":"fork-context-ref","sessionId":"` + sid1 + `","forkedFromSession":"` + strings.ToUpper(sid2) + `","uuid":"00000000-0000-4000-8000-0000000000ff"}` + "\n")
	f.WriteString(`{"type":"user","uuid":"00000000-0000-4000-8000-0000000000fe","sessionId":"` + sid3 + `","message":{"role":"user","content":"copied"}}` + "\n")
	f.WriteString("{not json}\n")
	f.WriteString(`{"type":"assistant","sessionId":"` + sid1 + `","slug":"later-slug"}`)
	f.Close()
	facts, err = claude.ScanTranscript(context.Background(), paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if facts.Title != "my renamed session" || facts.TrailingNL || facts.Slug != "later-slug" {
		t.Errorf("title %q trailingNL %v slug %q", facts.Title, facts.TrailingNL, facts.Slug)
	}
	if !reflect.DeepEqual(facts.ForkRefs, []string{sid2}) || !reflect.DeepEqual(facts.CopiedSIDs, []string{sid3}) {
		t.Errorf("fork refs %v copied %v", facts.ForkRefs, facts.CopiedSIDs)
	}
	if _, err := claude.ScanTranscript(context.Background(), filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Error("missing transcript scanned")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := claude.ScanTranscript(ctx, paths[0]); err == nil {
		t.Error("cancelled scan succeeded")
	}
	// The first prompt is the title when nothing else is.
	p := filepath.Join(dir, "plain.jsonl")
	os.WriteFile(p, []byte(`{"type":"user","isMeta":true,"message":{"role":"user","content":"meta"}}`+"\n"+
		`{"type":"user","message":{"role":"user","content":"<command-name>/clear</command-name>"}}`+"\n"+
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"first real prompt"}]}}`+"\n"), 0o600)
	if facts, _ := claude.ScanTranscript(context.Background(), p); facts.Title != "first real prompt" {
		t.Errorf("first-prompt title = %q", facts.Title)
	}
	long := filepath.Join(dir, "long.jsonl")
	os.WriteFile(long, []byte(`{"type":"ai-title","aiTitle":"`+strings.Repeat("é", 500)+`"}`+"\n"), 0o600)
	if facts, _ := claude.ScanTranscript(context.Background(), long); len([]rune(facts.Title)) != 200 {
		t.Errorf("title not bounded: %d runes", len([]rune(facts.Title)))
	}
}

func TestScanLinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l := claudetest.New(t, filepath.Join(dir, "fake"))
	s := claudetest.Session{SID: sid1, Cwd: filepath.Join(dir, "work"), Lines: 14}
	paths := l.WriteSession(t, s)
	orig, _ := os.ReadFile(paths[0])
	c, err := claude.ScanLinks(context.Background(), bytes.NewReader(orig))
	if err != nil || !c.Valid || !c.TrailingNL || c.Records != 14 || len(c.UUIDs) == 0 {
		t.Fatalf("original: %+v %v", c, err)
	}
	if c.FirstParent != "" {
		t.Errorf("the first record of a session has no parent, got %q", c.FirstParent)
	}
	// Claude recreates <sid>.jsonl after a move (E8): the fragment's first
	// record links into the original, and their uuids are disjoint.
	os.Rename(paths[0], paths[0]+".moved")
	frag := l.AppendFragment(t, s, 3)
	fb, _ := os.ReadFile(frag)
	fl, err := claude.ScanLinks(context.Background(), bytes.NewReader(fb))
	if err != nil || !fl.Valid || fl.Records != 3 || !c.UUIDs[fl.FirstParent] {
		t.Fatalf("fragment: %+v %v (first parent must be a uuid of the original)", fl, err)
	}
	for u := range fl.UUIDs {
		if c.UUIDs[u] {
			t.Fatalf("fragment and original share uuid %s", u)
		}
	}
	// No trailing newline; a broken line; blank lines are ignored.
	nn, _ := claude.ScanLinks(context.Background(), strings.NewReader(`{"uuid":"a"}`+"\n\n"+`{"uuid":"b","parentUuid":"a"}`))
	if !nn.Valid || nn.TrailingNL || nn.Records != 2 || !nn.UUIDs["a"] || !nn.UUIDs["b"] {
		t.Errorf("no newline: %+v", nn)
	}
	logical, _ := claude.ScanLinks(context.Background(), strings.NewReader(`{"type":"ai-title","aiTitle":"x"}`+"\n"+`{"uuid":"c","parentUuid":null,"logicalParentUuid":"z"}`+"\n"))
	if logical.FirstParent != "" || logical.FirstLogicalParent != "z" {
		t.Errorf("logical parent: %+v", logical)
	}
	for _, bad := range []string{"{torn", "null\n", "[1]\n", `{"uuid":"a"}` + "\nnot json\n"} {
		if got, err := claude.ScanLinks(context.Background(), strings.NewReader(bad)); err != nil || got.Valid {
			t.Errorf("%q: %+v %v, want invalid", bad, got, err)
		}
	}
	if got, _ := claude.ScanLinks(context.Background(), strings.NewReader("")); got.TrailingNL || got.Records != 0 || !got.Valid {
		t.Errorf("empty stream: %+v", got)
	}
}

func TestParseResumeTable(t *testing.T) {
	t.Parallel()
	upper := strings.ToUpper(sid1)
	cases := []struct {
		args []string
		want harness.Resume
	}{
		{nil, harness.Resume{}},
		{[]string{"-p", "hello"}, harness.Resume{}},
		{[]string{"--resume", sid1}, harness.Resume{Kind: harness.ResumeSID, Value: sid1}},
		{[]string{"-r", upper}, harness.Resume{Kind: harness.ResumeSID, Value: sid1}},
		{[]string{"--resume=" + sid1, "--fork-session"}, harness.Resume{Kind: harness.ResumeSID, Value: sid1, Fork: true}},
		{[]string{"--resume", "/u/cc/projects/p/" + sid1 + ".jsonl"}, harness.Resume{Kind: harness.ResumePath, Value: "/u/cc/projects/p/" + sid1 + ".jsonl"}},
		{[]string{"--resume", "refactor notes"}, harness.Resume{Kind: harness.ResumeName, Value: "refactor notes"}},
		{[]string{"--resume"}, harness.Resume{Kind: harness.ResumePicker}},
		{[]string{"-r", "--model", "x"}, harness.Resume{Kind: harness.ResumePicker}},
		{[]string{"--resume="}, harness.Resume{Kind: harness.ResumePicker}},
		{[]string{"-c"}, harness.Resume{Kind: harness.ResumeContinue}},
		{[]string{"--continue", "--fork-session"}, harness.Resume{Kind: harness.ResumeContinue, Fork: true}},
		{[]string{"-c", "-r", sid1}, harness.Resume{Kind: harness.ResumeSID, Value: sid1}},
		{[]string{"attach", "job-7"}, harness.Resume{Kind: harness.ResumeJob, Value: "job-7"}},
		{[]string{"respawn", "job-7"}, harness.Resume{Kind: harness.ResumeJob, Value: "job-7"}},
		{[]string{"say", "attach", "job-7"}, harness.Resume{}},
		{[]string{"--", "--resume", sid1}, harness.Resume{}},
	}
	for _, c := range cases {
		if got := claude.ParseResume(c.args); got != c.want {
			t.Errorf("ParseResume(%q) = %+v, want %+v", c.args, got, c.want)
		}
	}
}

// D32: the exact inline settings of managed launches.
func TestSettingsJSON(t *testing.T) {
	t.Parallel()
	want := `{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}`
	if got := claude.SettingsJSON(config.Default().Policy); got != want {
		t.Fatalf("SettingsJSON = %s", got)
	}
}

func TestCleanupPeriodDays(t *testing.T) {
	t.Parallel()
	l := layout(t)
	if d, err := claude.CleanupPeriodDays(l.ConfigDir); d != 30 || err != nil {
		t.Fatalf("no settings: %d %v", d, err)
	}
	settings := filepath.Join(l.ConfigDir, "settings.json")
	for data, want := range map[string]int{`{"cleanupPeriodDays":45}`: 45, `{"theme":"dark"}`: 30, `{"cleanupPeriodDays":0}`: 0} {
		os.WriteFile(settings, []byte(data), 0o600)
		if d, err := claude.CleanupPeriodDays(l.ConfigDir); d != want || err != nil {
			t.Errorf("%s: %d %v", data, d, err)
		}
	}
	for _, bad := range []string{`{"cleanupPeriodDays":-3}`, `{"cleanupPeriodDays":2.5}`, `{"cleanupPeriodDays":"x"}`, `{broken`} {
		os.WriteFile(settings, []byte(bad), 0o600)
		if d, err := claude.CleanupPeriodDays(l.ConfigDir); d != 30 || err == nil {
			t.Errorf("%s: %d %v, want the default with an error", bad, d, err)
		}
	}
}
