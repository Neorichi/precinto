package testkit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

var markerSeq atomic.Uint64

// marker implements Marker: "precinto-marker-<n>-<20 hex>", unique within
// the process (counter) and across processes (80 random bits). It uses only
// [a-z0-9-], so it appears verbatim in JSON, shell, TOML and Markdown, and it
// never trips Hygiene.
func marker(t testing.TB) string {
	t.Helper()
	var b [10]byte
	_, _ = rand.Read(b[:]) // never fails (Go ≥ 1.24)
	return fmt.Sprintf("precinto-marker-%d-%x", markerSeq.Add(1), b)
}

// excludeSet holds GrepTree's exclude patterns (slash-separated, relative to
// the searched directory). A pattern without '/' matches any path element
// at any depth, like a .gitignore name ("capsules", "*.pcap"); a pattern
// with '/' matches the relative path of an entry or of one of its parent
// directories ("state/sessions", "capsules/*/x"). An absolute pattern names
// a directory or file below the searched directory literally. Patterns use
// path.Match syntax.
type excludeSet struct {
	names []string // patterns without '/'
	rels  []string // patterns with '/'
}

// newExcludeSet compiles patterns for a search of dir, which resolves to
// root (an absolute pattern may be written against either form).
func newExcludeSet(dir, root string, patterns []string) (excludeSet, error) {
	var ex excludeSet
	for _, p := range patterns {
		if filepath.IsAbs(p) {
			rel, ok := relBelow([]string{dir, root}, p)
			if !ok {
				return ex, fmt.Errorf("exclude %q is not below %s", p, dir)
			}
			ex.rels = append(ex.rels, escapeGlob(filepath.ToSlash(rel)))
			continue
		}
		p = strings.Trim(path.Clean(filepath.ToSlash(p)), "/")
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") {
			return ex, fmt.Errorf("exclude %q matches nothing below the directory", p)
		}
		if _, err := path.Match(p, ""); err != nil {
			return ex, fmt.Errorf("exclude %q: %w", p, err)
		}
		if strings.Contains(p, "/") {
			ex.rels = append(ex.rels, p)
		} else {
			ex.names = append(ex.names, p)
		}
	}
	return ex, nil
}

// relBelow returns p relative to the first base it lies below, trying p as
// written and with its symlinks resolved.
func relBelow(bases []string, p string) (string, bool) {
	forms := []string{filepath.Clean(p)}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		forms = append(forms, real)
	}
	for _, f := range forms {
		for _, b := range bases {
			if rel, err := filepath.Rel(b, f); err == nil && rel != "." && filepath.IsLocal(rel) {
				return rel, true
			}
		}
	}
	return "", false
}

func escapeGlob(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[]\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// match reports whether the entry at rel (slash-separated) is excluded.
func (ex excludeSet) match(rel string) bool {
	elems := strings.Split(rel, "/")
	for _, pat := range ex.names {
		for _, e := range elems {
			if ok, _ := path.Match(pat, e); ok {
				return true
			}
		}
	}
	for _, pat := range ex.rels {
		for i := range elems {
			if ok, _ := path.Match(pat, strings.Join(elems[:i+1], "/")); ok {
				return true
			}
		}
	}
	return false
}

// grepTree implements GrepTree: every entry below dir (never following
// symlinks) whose content, name or symlink target contains marker, as
// filepath.Join(dir, rel), sorted. A file that cannot be read is an error
// of the test and is reported among the hits as well (fail closed).
func grepTree(t testing.TB, dir, marker string, exclude []string) []string {
	t.Helper()
	if marker == "" {
		t.Fatalf("testkit.GrepTree: empty marker")
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("testkit.GrepTree: %v", err)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		t.Fatalf("testkit.GrepTree: %s is not a directory (%v)", dir, err)
	}
	ex, err := newExcludeSet(dir, root, exclude)
	if err != nil {
		t.Fatalf("testkit.GrepTree: %v", err)
	}
	m := []byte(marker)
	var hits []string
	hit := func(rel string) { hits = append(hits, filepath.Join(dir, filepath.FromSlash(rel))) }
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if err != nil {
			t.Errorf("testkit.GrepTree: cannot search %s: %v", rel, err)
			hit(rel)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}
		if ex.match(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case strings.Contains(rel, marker):
			hit(rel)
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				t.Errorf("testkit.GrepTree: cannot read link %s: %v", rel, err)
				hit(rel)
			} else if strings.Contains(target, marker) {
				hit(rel)
			}
		case d.Type().IsRegular():
			found, err := fileContains(p, m)
			if err != nil {
				t.Errorf("testkit.GrepTree: cannot search %s: %v", rel, err)
			}
			if found || err != nil {
				hit(rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("testkit.GrepTree: %v", err)
	}
	sort.Strings(hits)
	return hits
}

// fileContains streams p looking for m.
func fileContains(p string, m []byte) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	keep := len(m) - 1
	buf := make([]byte, 0, scanWindow+keep)
	for {
		n, rerr := io.ReadFull(f, buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if bytes.Contains(buf, m) {
			return true, nil
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			return false, nil
		}
		if rerr != nil {
			return false, rerr
		}
		if len(buf) > keep {
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
	}
}
