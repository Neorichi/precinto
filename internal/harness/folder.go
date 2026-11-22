package harness

import (
	"path/filepath"
	"strings"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
)

// InFolder reports whether p lies inside the folder dir by the rule
// config.RootsFor applies to protected folders (D93): component by
// component (paths.Within), and on darwin, for a folder whose path holds
// non-ASCII bytes, also by identity, so a path a harness reports in one
// Unicode normalization matches the folder recorded in the other (Claude
// Code reports NFC, getcwd and Finder's names are often NFD). Every
// comparison of a harness-reported path with a folder uses it (D136).
func InFolder(dir, p string) bool {
	if dir == "" || p == "" {
		return false
	}
	_, ok := config.Config{Roots: []config.Root{{ID: "folder", Path: dir}}}.RootFor(p)
	return ok
}

// RelInFolder returns p relative to the folder dir when p lies inside it
// (InFolder). When p names the folder in another spelling, the part below
// the folder is p's and the folder part is dir's own: the ancestor of p
// that is dir's directory (same device and inode, symlinks not followed)
// is cut off, so a unit, a marker or a restore under the folder uses one
// path whichever spelling the harness reported (D136).
func RelInFolder(dir, p string) (string, bool) {
	if !filepath.IsAbs(dir) || !filepath.IsAbs(p) || !InFolder(dir, p) {
		return "", false
	}
	dir, p = filepath.Clean(dir), filepath.Clean(p)
	if rel, err := filepath.Rel(dir, p); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
		return rel, true
	}
	want, err := fsx.Lstat(dir)
	if err != nil {
		return "", false
	}
	for a := p; ; a = filepath.Dir(a) {
		if st, err := fsx.Lstat(a); err == nil && st.SameFile(want) {
			rel, err := filepath.Rel(a, p)
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				return "", false
			}
			return rel, true
		}
		if filepath.Dir(a) == a {
			return "", false
		}
	}
}
