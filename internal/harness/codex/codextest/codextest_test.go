package codextest_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness/codex/codextest"
)

const marker = "CODEXTEST-MARKER-41c9"

var (
	// rolloutRE is the rollout layout of Codex 0.154 (SPEC §7.2):
	// sessions/YYYY/MM/DD/rollout-YYYY-MM-DDThh-mm-ss-<thread uuid>.jsonl.
	rolloutRE = regexp.MustCompile(`^sessions/(\d{4})/(\d{2})/(\d{2})/rollout-((\d{4})-(\d{2})-(\d{2})T\d{2}-\d{2}-\d{2})-([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.jsonl$`)
	uuidRE    = `[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`
)

// threadOf returns the thread id in a rollout file name.
func threadOf(t *testing.T, path string) string {
	t.Helper()
	m := regexp.MustCompile(`-(` + uuidRE + `)\.jsonl(\.zst)?$`).FindStringSubmatch(path)
	if m == nil {
		t.Fatalf("%s is not a rollout name", path)
	}
	return m[1]
}

func TestNewWritesTheHome(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "codex-home")
	const age = 2 * time.Hour
	before := time.Now()
	h := codextest.New(t, dir, codextest.Options{Rollouts: 3, Marker: marker, WithWAL: true, WithLocks: true, RolloutAge: age})
	after := time.Now()
	if h.Dir != dir {
		t.Fatalf("Home.Dir = %s, want %s", h.Dir, dir)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home mode: %v %v", fi, err)
	}

	// The whole layout, file by file: (pattern, count, holds content).
	layout := []struct {
		re      string
		n       int
		content bool // content class: carries the marker; never-touch and -shm files must not
	}{
		{rolloutRE.String(), 3, true},
		{`^history\.jsonl$`, 1, true},
		{`^session_index\.jsonl$`, 1, true},
		{`^state_5\.sqlite$`, 1, true},
		{`^logs_2\.sqlite$`, 1, true},
		{`^thread_history_1\.sqlite$`, 1, true},
		{`^state_5\.sqlite-wal$`, 1, true},
		{`^state_5\.sqlite-shm$`, 1, false},
		{`^shell_snapshots/` + uuidRE + `\.\d+\.sh$`, 1, true},
		{`^auth\.json$`, 1, false},
		{`^config\.toml$`, 1, false},
		{`^thread-writer-locks/\.coordination\.lock$`, 1, false},
		{`^thread-writer-locks/` + uuidRE + `\.lock$`, 3, false},
	}
	files := regularFiles(t, dir)
	counts := make([]int, len(layout))
	for _, rel := range files {
		matched := false
		for i, e := range layout {
			if regexp.MustCompile(e.re).MatchString(rel) {
				counts[i]++
				matched = true
				has := bytes.Contains(readFile(t, filepath.Join(dir, rel)), []byte(marker))
				if has != e.content {
					t.Errorf("%s: marker present = %v, want %v", rel, has, e.content)
				}
			}
		}
		if !matched {
			t.Errorf("unexpected file %s", rel)
		}
		if strings.Contains(rel, marker) {
			t.Errorf("%s: the marker leaked into a file name", rel)
		}
	}
	for i, e := range layout {
		if counts[i] != e.n {
			t.Errorf("%d files match %s, want %d", counts[i], e.re, e.n)
		}
	}

	// Rollouts: names, dates and ids agree with session_meta; the marker is
	// in the prompt and the tool inputs; the newest is RolloutAge old.
	rolls := h.Rollouts(t)
	if len(rolls) != 3 {
		t.Fatalf("Rollouts = %v", rolls)
	}
	ids := map[string]bool{}
	var prevEnd time.Time
	for i, p := range rolls {
		rel, _ := filepath.Rel(dir, p)
		m := rolloutRE.FindStringSubmatch(filepath.ToSlash(rel))
		if m == nil {
			t.Fatalf("%s does not match the rollout layout", rel)
		}
		if m[1] != m[5] || m[2] != m[6] || m[3] != m[7] {
			t.Errorf("%s: directory date differs from the name's date", rel)
		}
		id := m[8]
		ids[id] = true
		recs := records(t, p)
		if len(recs) < 5 || str(recs[0], "type") != "session_meta" {
			t.Fatalf("%s: first line %v", rel, recs[0])
		}
		meta, _ := recs[0]["payload"].(map[string]any)
		if str(meta, "id") != id || str(meta, "session_id") != id || str(meta, "cwd") == "" || str(meta, "cli_version") != "0.154.0" {
			t.Errorf("%s: session_meta %v", rel, meta)
		}
		start, err := time.Parse(time.RFC3339Nano, str(meta, "timestamp"))
		if err != nil {
			t.Fatal(err)
		}
		if local := start.In(time.Local).Format("2006-01-02T15-04-05"); local != m[4] {
			t.Errorf("%s: name time %s, session_meta %s (local)", rel, m[4], local)
		}
		if !strings.HasPrefix(id, "00000000-0000-7000-8000-") {
			t.Errorf("%s: thread id %s is not in the fixture form", rel, id)
		}
		for j, r := range recs {
			if r["ordinal"] != float64(j) || str(r, "timestamp") == "" || r["payload"] == nil {
				t.Errorf("%s line %d: envelope %v", rel, j, r)
			}
		}
		raw := string(readFile(t, p))
		for _, want := range []string{`"type":"input_text","text":"` + marker, "*** Add File: docs/notes-", `"name":"apply_patch"`} {
			if !strings.Contains(raw, want) {
				t.Errorf("%s lacks %q", rel, want)
			}
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.ModTime().After(after.Add(-age)) {
			t.Errorf("%s: mtime %v is younger than RolloutAge", rel, fi.ModTime())
		}
		if i > 0 && !fi.ModTime().After(prevEnd) {
			t.Errorf("%s: rollouts are not in time order", rel)
		}
		prevEnd = fi.ModTime()
		if perm := fi.Mode().Perm(); perm&0o600 != 0o600 || perm&^0o644 != 0 {
			t.Errorf("%s: mode %v, want 0644 (umask permitting)", rel, perm)
		}
	}
	if newest := prevEnd; newest.Before(before.Add(-age - time.Millisecond)) {
		t.Errorf("newest rollout mtime %v, want now-%v", newest, age)
	}

	for _, r := range records(t, filepath.Join(dir, "history.jsonl")) {
		if !ids[str(r, "session_id")] || !strings.Contains(str(r, "text"), marker) || r["ts"] == nil {
			t.Errorf("history line %v", r)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "history.jsonl")); fi.Mode().Perm() != 0o600 {
		t.Errorf("history.jsonl mode %v, want 0600", fi.Mode().Perm())
	}
	for _, r := range records(t, filepath.Join(dir, "session_index.jsonl")) {
		if _, err := time.Parse(time.RFC3339Nano, str(r, "updated_at")); err != nil || !ids[str(r, "id")] || !strings.Contains(str(r, "thread_name"), marker) {
			t.Errorf("session_index line %v", r)
		}
	}

	// SQLite files are opaque bytes that look like SQLite; the WAL has its
	// magic; the -shm holds no content.
	for _, db := range []string{"state_5.sqlite", "logs_2.sqlite", "thread_history_1.sqlite"} {
		b := readFile(t, filepath.Join(dir, db))
		if !bytes.HasPrefix(b, []byte("SQLite format 3\x00")) || len(b)%4096 != 0 {
			t.Errorf("%s: not SQLite-shaped (%d bytes)", db, len(b))
		}
	}
	if wal := readFile(t, filepath.Join(dir, "state_5.sqlite-wal")); binary.BigEndian.Uint32(wal) != 0x377f0682 {
		t.Errorf("state_5.sqlite-wal lacks the WAL magic")
	}
	if shm := readFile(t, filepath.Join(dir, "state_5.sqlite-shm")); len(bytes.Trim(shm, "\x00")) != 0 {
		t.Errorf("state_5.sqlite-shm holds data")
	}

	// Placeholders: synthetic auth, a config whose sqlite_home and log_dir
	// keys PrepareHome must strip.
	cfg := string(readFile(t, filepath.Join(dir, "config.toml")))
	for _, key := range []string{"\nmodel = ", "\nsqlite_home = ", "\nlog_dir = ", "[history]"} {
		if !strings.Contains(cfg, key) {
			t.Errorf("config.toml lacks %q", key)
		}
	}
	var auth map[string]any
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "auth.json")), &auth); err != nil || auth["tokens"] == nil {
		t.Errorf("auth.json %v %v", auth, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "auth.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("auth.json mode %v, want 0600", fi.Mode().Perm())
	}

	// One empty writer lock per rollout (unheld: TestWithLocksAreUnheld).
	for id := range ids {
		lock := filepath.Join(dir, "thread-writer-locks", id+".lock")
		if fi, err := os.Stat(lock); err != nil || fi.Size() != 0 {
			t.Errorf("%s: %v %v", lock, fi, err)
		}
	}
}

func TestNewMinimalHome(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := codextest.New(t, dir, codextest.Options{})
	want := []string{"auth.json", "config.toml", "logs_2.sqlite", "state_5.sqlite", "thread_history_1.sqlite"}
	if got := regularFiles(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("files %v, want %v", got, want)
	}
	if r := h.Rollouts(t); len(r) != 0 {
		t.Fatalf("Rollouts = %v", r)
	}
}

func TestNewKeepsSeededPlaceholders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seeded := map[string]string{"config.toml": "model = \"seeded\"\n", "auth.json": "{\"seeded\":true}\n"}
	for name, content := range seeded {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	codextest.New(t, dir, codextest.Options{Rollouts: 1, Marker: marker})
	for name, content := range seeded {
		if got := string(readFile(t, filepath.Join(dir, name))); got != content {
			t.Errorf("%s replaced: %q", name, got)
		}
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, fn := range map[string]func(tb testing.TB){
		"relative dir":      func(tb testing.TB) { codextest.New(tb, "codex-home", codextest.Options{}) },
		"empty dir":         func(tb testing.TB) { codextest.New(tb, "", codextest.Options{}) },
		"negative rollouts": func(tb testing.TB) { codextest.New(tb, dir, codextest.Options{Rollouts: -1}) },
		"quote in marker":   func(tb testing.TB) { codextest.New(tb, dir, codextest.Options{Marker: `a"b`}) },
		"control in marker": func(tb testing.TB) { codextest.New(tb, dir, codextest.Options{Marker: "a\tb"}) },
	} {
		expectFatal(t, fn)
		if files := regularFiles(t, dir); len(files) != 0 {
			t.Fatalf("%s: files written before failing: %v", name, files)
		}
	}
	// Fixtures never clobber content: a second New over the same home fails
	// and leaves the first home's history as it was.
	codextest.New(t, dir, codextest.Options{Rollouts: 1, Marker: marker})
	hist := readFile(t, filepath.Join(dir, "history.jsonl"))
	msg := expectFatal(t, func(tb testing.TB) { codextest.New(tb, dir, codextest.Options{Rollouts: 1, Marker: marker}) })
	if !strings.Contains(msg, "exists") || !bytes.Equal(hist, readFile(t, filepath.Join(dir, "history.jsonl"))) {
		t.Fatalf("second New: %q", msg)
	}
}

func TestRolloutsListsCodexRolloutNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := codextest.New(t, dir, codextest.Options{Rollouts: 3, Marker: marker})
	rolls := h.Rollouts(t)
	if len(rolls) != 3 {
		t.Fatalf("Rollouts = %v", rolls)
	}
	// Codex discovers rollout-*.jsonl and rollout-*.jsonl.zst under
	// sessions/ and archived_sessions/; nothing else is a rollout.
	day := filepath.Dir(rolls[0])
	extra := map[string]bool{
		filepath.Join(dir, "archived_sessions", "2026", "01", "02", "rollout-2026-01-02T03-04-05-0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl.zst"): true,
		filepath.Join(day, "notes.txt"):           false,
		filepath.Join(day, "rollout-broken.json"): false,
	}
	for p := range extra {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(rolls[0], filepath.Join(day, "rollout-link.jsonl")); err != nil {
		t.Fatal(err)
	}
	got := h.Rollouts(t)
	want := append([]string{}, rolls...)
	for p, ok := range extra {
		if ok {
			want = append(want, p)
		}
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Rollouts =\n%v\nwant\n%v", got, want)
	}
	if err := os.Remove(rolls[1]); err != nil {
		t.Fatal(err)
	}
	if got := h.Rollouts(t); len(got) != 3 {
		t.Fatalf("after a removal: %v", got)
	}
	if err := os.RemoveAll(filepath.Join(dir, "sessions")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "archived_sessions")); err != nil {
		t.Fatal(err)
	}
	if got := h.Rollouts(t); len(got) != 0 {
		t.Fatalf("without sessions/: %v", got)
	}
	expectFatal(t, func(tb testing.TB) { (*codextest.Home)(nil).Rollouts(tb) })
	expectFatal(t, func(tb testing.TB) { (&codextest.Home{Dir: "relative"}).Rollouts(tb) })
}

// TestNothingOutsideTheHome checks that New, Rollouts and HoldWriterLock
// change nothing outside the home: a sibling canary, the test's working
// directory, and the paths recorded in content (only fixture paths under
// the test's temp dir, S13).
func TestNothingOutsideTheHome(t *testing.T) {
	outer := t.TempDir()
	canary := filepath.Join(outer, "canary")
	if err := os.Mkdir(canary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(canary, "keep.txt"), []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	canaryBefore, cwdBefore := dirListing(t, canary), dirListing(t, ".")

	home := filepath.Join(outer, "home")
	h := codextest.New(t, home, codextest.Options{Rollouts: 2, Marker: marker, WithWAL: true, WithLocks: true, RolloutAge: time.Minute})
	release := h.HoldWriterLock(t, threadOf(t, h.Rollouts(t)[0]))
	release()

	entries, err := os.ReadDir(outer)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"canary", "home"}) {
		t.Fatalf("outside the home: %v (the recorded cwd must never be created)", names)
	}
	if !reflect.DeepEqual(dirListing(t, canary), canaryBefore) {
		t.Fatal("the canary changed")
	}
	if !reflect.DeepEqual(dirListing(t, "."), cwdBefore) {
		t.Fatal("the working directory changed")
	}
	for _, rel := range regularFiles(t, home) {
		p := filepath.Join(home, rel)
		var abs []string
		switch {
		case strings.HasSuffix(rel, ".jsonl") || strings.HasSuffix(rel, ".json"):
			for _, line := range bytes.Split(readFile(t, p), []byte("\n")) {
				var v any
				if json.Unmarshal(line, &v) == nil {
					absoluteStrings(v, &abs)
				}
			}
		case strings.HasSuffix(rel, ".toml"):
			for _, m := range regexp.MustCompile(`"(/[^"]*)"`).FindAllStringSubmatch(string(readFile(t, p)), -1) {
				abs = append(abs, m[1])
			}
		}
		for _, a := range abs {
			if !strings.HasPrefix(a, outer+string(filepath.Separator)) {
				t.Errorf("%s records %q, outside the test's temp dir", rel, a)
			}
		}
	}
}
