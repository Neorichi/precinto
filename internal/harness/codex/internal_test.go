package codex

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/config"
)

func TestParseTOMLForms(t *testing.T) {
	t.Parallel()
	src := "# comment\r\n" +
		"a = 1\n" +
		"b.c = \"x\\u00e9\\\"q\" # trailing comment\n" +
		"'lit key' = 'raw \\ value'\n" +
		"ml = \"\"\"\nline one \\\n   continued\nend\"\"\"\n" +
		"ml2 = '''\n[not a table]\n'''\n" +
		"arr = [\n  1, # one\n  \"two\",\n  [3],\n]\n" +
		"inl = { x = 1, y.z = \"w\", n = { q = true } }\n" +
		"dt = 1979-05-27T07:32:00Z\n" +
		"f = -1.5e3\n" +
		"\n[t]\nk = false\n\n[[arr.tables]]\nx = 1\n" +
		"[ \"quoted\" . sub ]\ny = 2\n"
	doc, err := parseTOML(src)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, st := range doc.stmts {
		keys = append(keys, strings.Join(append(append([]string{}, st.table...), st.key...), "."))
	}
	want := []string{"a", "b.c", "lit key", "ml", "ml2", "arr", "inl", "dt", "f", "t", "t.k", "arr.tables", "arr.tables.x", "quoted.sub", "quoted.sub.y"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("statements = %v\nwant %v", keys, want)
	}
	if v := doc.stmts[1].value; v != "xé\"q" {
		t.Errorf("basic string = %q", v)
	}
	if v := doc.stmts[2].value; v != `raw \ value` {
		t.Errorf("literal string = %q", v)
	}
	if v := doc.stmts[3].value; v != "line one continued\nend" {
		t.Errorf("multi-line = %q", v)
	}
	if v := doc.stmts[4].value; v != "[not a table]\n" {
		t.Errorf("multi-line literal = %q", v)
	}
	inl := doc.stmts[6].value.(map[string]any)
	if inl["y"].(map[string]any)["z"] != "w" || inl["n"].(map[string]any)["q"] != true {
		t.Errorf("inline table = %v", inl)
	}
	for _, bad := range []string{
		"a = \n", "a 1\n", "[t\n", "a = \"unterminated\n", "a = 'x\n", "a = { x = 1\n", "a = [1, 2\n",
		"a = 1 b = 2\n", "a = \"\\q\"\n", "a = \"\"\"never closed\n", "\"\"\"k\"\"\" = 1\n", "a = { x = 1, x = 2 }\n",
		"a = \x01\n", "a = 1\rb = 2\n", "a = \"\xff\"\n",
	} {
		if _, err := parseTOML(bad); err == nil {
			t.Errorf("parseTOML(%q) accepted invalid TOML", bad)
		}
	}
}

func TestStrippedConfigOnlyTouchesRootKeys(t *testing.T) {
	t.Parallel()
	src := "sqlite_home = \"/x\"\nkeep = 1\nlog_dir = '''\n/y'''\n\n[profiles.p]\nsqlite_home = \"/kept/in/a/table\"\n"
	out, err := strippedConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	if out != "keep = 1\n\n[profiles.p]\nsqlite_home = \"/kept/in/a/table\"\n" {
		t.Fatalf("stripped = %q", out)
	}
	if _, err := strippedConfig("bad = = 1"); err == nil {
		t.Fatal("unparseable config stripped")
	}
}

func TestKeepTrustRefusesInlineHooks(t *testing.T) {
	t.Parallel()
	old := "[hooks.state.\"k\"]\ntrusted_hash = \"h\"\n"
	if _, err := keepTrust("hooks = { state = { other = { trusted_hash = \"x\" } } }\n", old); err == nil {
		t.Fatal("appending tables to an inline hooks table must fail")
	}
	if _, err := keepTrust("[hooks]\nstate = { k = { trusted_hash = \"x\" }, j = { trusted_hash = \"y\" } }\n", old); err == nil {
		t.Fatal("an entry inside an inline table cannot be replaced")
	}
	out, err := keepTrust("[hooks.state]\n\"k\" = { trusted_hash = \"user\" }\n\"j\".trusted_hash = \"keep\"\n", old)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseTOML(out)
	if err != nil {
		t.Fatal(err)
	}
	st := doc.hookStates()
	if st["k"].trustedHash != "h" || st["j"].trustedHash != "keep" || strings.Contains(out, "user") {
		t.Fatalf("merged:\n%s", out)
	}
	if out, err := keepTrust("a = 1\n", "no hooks = here"); err == nil {
		t.Fatalf("unparseable per-root config must fail, got %q", out)
	}
}

func TestWrongHomeRollouts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	user := filepath.Join(dir, "codex-user")
	c := config.Default()
	c.Roots = []config.Root{{ID: "root-acme", Path: filepath.Join(dir, "work", "acme")}}
	write := func(rel, data string) {
		p := filepath.Join(user, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(data), 0o600)
	}
	meta := func(cwd string) string {
		return `{"timestamp":"t","type":"session_meta","payload":{"id":"x","cwd":"` + cwd + `"}}` + "\n" +
			`{"type":"response_item","payload":{"type":"message","cwd":"` + filepath.Join(dir, "work", "acme") + `"}}` + "\n"
	}
	write("sessions/2026/11/21/rollout-a.jsonl", meta(filepath.Join(dir, "work", "acme", "src")))
	write("archived_sessions/rollout-b.jsonl", meta(filepath.Join(dir, "work", "acme")))
	write("sessions/2026/11/21/rollout-c.jsonl", meta(filepath.Join(dir, "elsewhere")))
	write("sessions/2026/11/21/rollout-d.jsonl.zst", "compressed")
	write("sessions/2026/11/21/rollout-e.jsonl", `{"type":"session_meta","payload":{"cwd":"`+strings.Repeat("x", maxMetaLine)+`"}}`)
	write("sessions/2026/11/21/rollout-f.jsonl", `{"type":"turn_context","payload":{"cwd":"`+filepath.Join(dir, "work", "acme")+`"}}`+"\n")
	write("sessions/2026/11/21/rollout-g.jsonl", "{broken\n")
	write("sessions/2026/11/21/notes.jsonl", meta(filepath.Join(dir, "work", "acme")))
	got, err := WrongHomeRollouts(context.Background(), user, c)
	if err != nil {
		t.Fatal(err)
	}
	// inside: a and b; could not be checked: the compressed d, the
	// oversized e and the broken g; outside (c) and another record type
	// (f) are not counted.
	if !reflect.DeepEqual(got, map[string]int{"root-acme": 2, "": 3}) {
		t.Fatalf("wrong-home rollouts = %v", got)
	}
	if got, err := WrongHomeRollouts(context.Background(), filepath.Join(dir, "missing"), c); err != nil || len(got) != 0 {
		t.Fatalf("missing home: %v %v", got, err)
	}
	if _, err := WrongHomeRollouts(context.Background(), "relative", c); err == nil {
		t.Fatal("relative home accepted")
	}
}

// The first-line reader keeps only the record type and the payload's cwd
// (moved here from internal/doctor, CC-18).
func TestSessionMetaCwd(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", 70<<10)
	metaLine := func(cwd string) string {
		return `{"timestamp":"2026-11-21T09:00:00.000Z","ordinal":0,"type":"session_meta","payload":{"session_id":"00000000-0000-7000-8000-000000000001","id":"00000000-0000-7000-8000-000000000001","cwd":"` + cwd + `","originator":"codex_cli_rs","cli_version":"0.154.0"}}`
	}
	cases := []struct {
		name, content string
		want          string
		st            metaStatus
	}{
		{"session_meta", metaLine("/u/work/acme") + "\n{\"type\":\"turn_context\"}\n", "/u/work/acme", metaOK},
		{"rest of the file is never parsed", metaLine("/u/work/acme") + "\n\x00\x01 not json at all", "/u/work/acme", metaOK},
		{"no newline", metaLine("/u/work/acme"), "/u/work/acme", metaOK},
		{"payload before type", `{"payload":{"cwd":"/u/a","instructions":"x"},"type":"session_meta"}` + "\n", "/u/a", metaOK},
		{"cwd before a long line's cut", `{"type":"session_meta","payload":{"cwd":"/u/a","instructions":"` + big + `"}}` + "\n", "/u/a", metaOK},
		{"cwd after the 64 KiB cut", `{"type":"session_meta","payload":{"instructions":"` + big + `","cwd":"/u/a"}}` + "\n", "", metaUnreadable},
		{"another record type", `{"type":"turn_context","payload":{"cwd":"/u/a"}}` + "\n", "", metaOther},
		{"cwd not a string", `{"type":"session_meta","payload":{"cwd":42}}` + "\n", "", metaUnreadable},
		{"relative cwd", `{"type":"session_meta","payload":{"cwd":"work/acme"}}` + "\n", "", metaUnreadable},
		{"no payload", `{"type":"session_meta"}` + "\n", "", metaUnreadable},
		{"not JSON", "garbage\n", "", metaUnreadable},
		{"empty", "", "", metaUnreadable},
		{"nested values are skipped", `{"type":"session_meta","payload":{"git":{"a":[1,{"b":"c"}]},"cwd":"/u/n"}}` + "\n", "/u/n", metaOK},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "rollout-"+string(rune('a'+i))+".jsonl")
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, st := sessionMetaCwd(p)
		if got != c.want || st != c.st {
			t.Errorf("%s: sessionMetaCwd = %q, %v; want %q, %v", c.name, got, st, c.want, c.st)
		}
	}
	if _, st := sessionMetaCwd(filepath.Join(dir, "missing.jsonl")); st != metaUnreadable {
		t.Error("a missing file has a cwd")
	}
}
