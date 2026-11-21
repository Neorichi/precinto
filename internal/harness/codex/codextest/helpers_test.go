package codextest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

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

// records decodes every line of a JSONL file.
func records(t *testing.T, path string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for i, l := range bytes.Split(bytes.TrimSuffix(readFile(t, path), []byte("\n")), []byte("\n")) {
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
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// absoluteStrings collects every string value and key of a JSON document
// that looks like an absolute path.
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
