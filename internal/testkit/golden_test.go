package testkit_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/testkit"
)

func goldenDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	writeFiles(t, dir, map[string]string{"testdata/hook/allow.json": "{\n  \"exit\": 0\n}\n"})
	return dir
}

func TestGoldenCompare(t *testing.T) {
	goldenDir(t)
	if r := record(t, func(tb testing.TB) { testkit.Golden(tb, "hook/allow.json", []byte("{\n  \"exit\": 0\n}\n")) }); r.Failed() {
		t.Errorf("equal content failed: %s", r.text())
	}
	for _, c := range []struct{ got, want string }{
		{"{\n  \"exit\": 1\n}\n", `line 2: want "  \"exit\": 0", got "  \"exit\": 1"`},
		{"{\n  \"exit\": 0\n}\nextra\n", `line 4: unexpected extra line "extra"`},
		{"{\n", `line 2: missing line`},
	} {
		r := record(t, func(tb testing.TB) { testkit.Golden(tb, "hook/allow.json", []byte(c.got)) })
		if r.fatal || !strings.Contains(r.text(), "testdata/hook/allow.json differs") || !strings.Contains(r.text(), c.want) {
			t.Errorf("mismatch report %q, want %q", r.text(), c.want)
		}
	}
	r := record(t, func(tb testing.TB) { testkit.Golden(tb, "hook/missing.json", []byte("x")) })
	if !strings.Contains(r.text(), "does not exist (run the test with -update") {
		t.Errorf("missing golden: %q", r.text())
	}
	for _, bad := range []string{"", "/abs", "../escape", "a/../b", "a//b", "./a"} {
		mustFatal(t, "is not a clean path inside testdata/", func(tb testing.TB) { testkit.Golden(tb, bad, nil) })
	}
}

func TestGoldenUpdateEnv(t *testing.T) {
	dir := goldenDir(t)
	t.Setenv("PRECINTO_UPDATE_GOLDEN", "1")
	if r := record(t, func(tb testing.TB) { testkit.Golden(tb, "new/deep/out.txt", []byte("fresh\n")) }); r.Failed() {
		t.Fatalf("update failed: %s", r.text())
	}
	b, err := os.ReadFile(filepath.Join(dir, "testdata", "new", "deep", "out.txt"))
	if err != nil || string(b) != "fresh\n" {
		t.Fatalf("golden not written: %q %v", b, err)
	}
	// Content that fails the hygiene rules is never written.
	r := record(t, func(tb testing.TB) {
		testkit.Golden(tb, "hook/allow.json", []byte(`{"cwd": "/Users/alice/work"}`))
	})
	if !strings.Contains(r.text(), "refusing to write testdata/hook/allow.json") || !strings.Contains(r.text(), "line 1: home directory path") {
		t.Errorf("hygiene refusal: %q", r.text())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "testdata", "hook", "allow.json")); strings.Contains(string(b), "alice") {
		t.Error("leaking content was written")
	}
}

func TestGoldenUpdateFlag(t *testing.T) {
	dir := goldenDir(t)
	f := flag.Lookup("update")
	if f == nil {
		t.Fatal("testkit does not register -update")
	}
	if err := f.Value.Set("true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Value.Set("false") })
	if r := record(t, func(tb testing.TB) { testkit.Golden(tb, "hook/allow.json", []byte("rewritten\n")) }); r.Failed() {
		t.Fatalf("update failed: %s", r.text())
	}
	if b, err := os.ReadFile(filepath.Join(dir, "testdata", "hook", "allow.json")); err != nil || string(b) != "rewritten\n" {
		t.Errorf("golden = %q %v", b, err)
	}
}
