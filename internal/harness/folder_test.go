package harness_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/precinto/precinto/internal/harness"
)

// D136: RelInFolder cuts a path at the folder whichever spelling it uses
// for it, and never through a symlink.
func TestRelInFolder(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "work", "acme")
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p    string
		rel  string
		want bool
	}{
		{filepath.Join(root, "docs", "notes.md"), "docs/notes.md", true},
		{root, ".", true},
		{filepath.Join(dir, "work", "acme2", "x.md"), "", false},
		{filepath.Join(dir, "link", "docs", "notes.md"), "", false}, // a symlink to the folder is not the folder
		{"relative/notes.md", "", false},
	} {
		rel, ok := harness.RelInFolder(root, tc.p)
		if ok != tc.want || filepath.ToSlash(rel) != tc.rel {
			t.Errorf("RelInFolder(%q) = %q, %v; want %q, %v", tc.p, rel, ok, tc.rel, tc.want)
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	nfd := filepath.Join(dir, "Diseño")
	nfc := filepath.Join(dir, "Diseño")
	if err := os.MkdirAll(filepath.Join(nfd, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if a, err := os.Stat(nfc); err != nil {
		t.Skipf("normalization-sensitive file system: %v", err)
	} else if b, _ := os.Stat(nfd); !os.SameFile(a, b) {
		t.Skip("NFC and NFD name different directories here")
	}
	for _, tc := range [][2]string{{nfd, nfc}, {nfc, nfd}} {
		rel, ok := harness.RelInFolder(tc[0], filepath.Join(tc[1], "docs", "notes.md"))
		if !ok || filepath.ToSlash(rel) != "docs/notes.md" {
			t.Errorf("RelInFolder(%q, other spelling) = %q, %v", tc[0], rel, ok)
		}
		if !harness.InFolder(tc[0], filepath.Join(tc[1], "docs")) {
			t.Errorf("InFolder(%q, other spelling) = false", tc[0])
		}
	}
}
