package fsx_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/testkit"
)

// testEpoch is a fixed mtime for tests (testkit.Epoch).
var testEpoch = testkit.Epoch

// tempDir returns a fresh, symlink-resolved test directory (t.TempDir lives
// below /var on darwin, which is a symlink to /private/var).
func tempDir(t testing.TB) string {
	t.Helper()
	d, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// openBase opens a fresh base directory and closes it at cleanup.
func openBase(t testing.TB) (*fsx.Dir, string) {
	t.Helper()
	root := tempDir(t)
	d, err := fsx.OpenBase(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, root
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// listTree returns every path below dir (relative, sorted) with its
// content for regular files, so tests can assert that a canary tree was
// neither written nor deleted.
func listTree(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		entry := rel + " " + fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			entry += " " + string(b)
		}
		out = append(out, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func equalLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
