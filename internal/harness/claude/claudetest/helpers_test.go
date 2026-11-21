package claudetest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fixtureUUIDRE matches the version-4 UUIDs claudetest derives.
var fixtureUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// fatalTB records failures instead of failing the real test; Fatal* end the
// calling goroutine like testing.T does.
type fatalTB struct {
	testing.TB
	mu   sync.Mutex
	msgs []string
}

func (f *fatalTB) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, s)
}

func (f *fatalTB) Helper() {}
func (f *fatalTB) Fatalf(format string, args ...any) {
	f.record(fmt.Sprintf(format, args...))
	runtime.Goexit()
}
func (f *fatalTB) Fatal(args ...any)                 { f.record(fmt.Sprint(args...)); runtime.Goexit() }
func (f *fatalTB) FailNow()                          { f.record("FailNow"); runtime.Goexit() }
func (f *fatalTB) Errorf(format string, args ...any) { f.record(fmt.Sprintf(format, args...)) }
func (f *fatalTB) Error(args ...any)                 { f.record(fmt.Sprint(args...)) }
func (f *fatalTB) Fail()                             { f.record("Fail") }
func (f *fatalTB) Failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs) > 0
}

// expectFatal runs fn on its own goroutine with a recording TB and returns
// the failure message; it fails t when fn did not fail.
func expectFatal(t *testing.T, fn func(tb testing.TB)) string {
	t.Helper()
	f := &fatalTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatalf("the helper accepted invalid input")
	}
	return strings.Join(f.msgs, "; ")
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jsonlLines splits a JSONL file into its lines (without '\n').
func jsonlLines(t *testing.T, path string) [][]byte {
	t.Helper()
	b := readFile(t, path)
	b = bytes.TrimSuffix(b, []byte("\n"))
	if len(b) == 0 {
		return nil
	}
	return bytes.Split(b, []byte("\n"))
}

// records decodes every line of a JSONL file.
func records(t *testing.T, path string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for i, l := range jsonlLines(t, path) {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("%s line %d does not parse: %v", path, i+1, err)
		}
		out = append(out, m)
	}
	return out
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// conversation returns the records that carry a uuid, in file order.
func conversation(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "uuid") != "" {
			out = append(out, r)
		}
	}
	return out
}

// uuidSet returns the uuids of a JSONL file.
func uuidSet(t *testing.T, path string) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, r := range conversation(records(t, path)) {
		set[str(r, "uuid")] = true
	}
	return set
}

// toolUses returns the tool_use blocks of assistant records.
func toolUses(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "type") != "assistant" {
			continue
		}
		msg, _ := r["message"].(map[string]any)
		blocks, _ := msg["content"].([]any)
		for _, b := range blocks {
			if m, ok := b.(map[string]any); ok && str(m, "type") == "tool_use" {
				out = append(out, m)
			}
		}
	}
	return out
}

// sessionRule is the fail-closed session-unit rule of SPEC §7.1.1: a path
// component equal to the sid, or a basename starting with "<sid>." or
// "<sid>-".
func sessionRule(rel, sid string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == sid {
			return true
		}
	}
	base := parts[len(parts)-1]
	return strings.HasPrefix(base, sid+".") || strings.HasPrefix(base, sid+"-")
}

// regularFiles lists every regular file below dir, relative to dir.
func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// absoluteStrings collects every string value and object key of a JSON
// document that looks like an absolute path.
func absoluteStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "/") {
			*out = append(*out, x)
		}
	case []any:
		for _, e := range x {
			absoluteStrings(e, out)
		}
	case map[string]any:
		for k, e := range x {
			absoluteStrings(k, out)
			absoluteStrings(e, out)
		}
	}
}

// dirListing snapshots names, sizes and mtimes of the entries of dir.
func dirListing(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s %d %d", e.Name(), fi.Size(), fi.ModTime().UnixNano()))
	}
	return out
}
