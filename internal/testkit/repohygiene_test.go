package testkit_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/testkit"
)

// moduleRoot walks up from the package directory (where go test runs) to
// the precinto go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(b), "module github.com/Neorichi/precinto\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("the precinto go.mod was not found above the test directory")
		}
		dir = parent
	}
}

// testdataDirs lists every testdata/ directory of the module, sorted,
// without descending into version-control metadata or nested modules.
func testdataDirs(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != root {
			switch d.Name() {
			case ".git", ".hg", ".svn":
				return fs.SkipDir
			case "testdata":
				dirs = append(dirs, p)
				return fs.SkipDir // nested testdata is part of this one
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return fs.SkipDir // another module
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// TestRepositoryTestdataHygiene is the S13 repository gate (TESTPLAN §1.2,
// §10): every testdata/ directory of the module — golden files, fixtures,
// helper programs — passes testkit.Hygiene, so CI rejects real paths,
// emails, tokens or non-fixture UUIDs in anything committed as test data.
func TestRepositoryTestdataHygiene(t *testing.T) {
	root := moduleRoot(t)
	dirs := testdataDirs(t, root)
	// testkit's own helper program lives under testdata/: the walk found
	// at least that one, or it is looking in the wrong place.
	found := false
	for _, d := range dirs {
		if filepath.ToSlash(d) == filepath.ToSlash(filepath.Join(root, "internal", "testkit", "testdata")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("internal/testkit/testdata not among the testdata directories %v", dirs)
	}
	for _, d := range dirs {
		rel, err := filepath.Rel(root, d)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.ToSlash(rel), func(t *testing.T) { testkit.Hygiene(t, d) })
	}
}

// TestTestdataDirsWalk: the walk finds nested testdata directories once,
// skips VCS metadata and nested modules.
func TestTestdataDirsWalk(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{
		"a/testdata/inner/testdata", "b/c/testdata", ".git/x/testdata", "nested/testdata", "plain/dir",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "go.mod"), []byte("module other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := testdataDirs(t, root)
	var rel []string
	for _, d := range got {
		r, _ := filepath.Rel(root, d)
		rel = append(rel, filepath.ToSlash(r))
	}
	if strings.Join(rel, ",") != "a/testdata,b/c/testdata" {
		t.Errorf("testdata dirs %v", rel)
	}
}
