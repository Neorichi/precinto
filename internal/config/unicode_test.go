package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/precinto/precinto/internal/config"
)

const (
	nfdName = "Disen\u0303o" // as Finder stores it
	nfcName = "Dise\u00f1o"  // as typed, and as Claude Code reports a cwd
)

// unicodeBase creates <tmp>/Dise\u00f1o stored in NFD and returns the
// resolved base. APFS ignores normalization: both spellings name it.
func unicodeBase(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("normalization-insensitive file system (APFS) only")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, nfdName, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, nfcName)); err != nil {
		t.Skip("this volume is normalization-sensitive")
	}
	return base
}

// D93 (H2): a root and a path that differ only in Unicode normalization
// name the same folder, in both directions.
func TestRootsForMatchesBothNormalizations(t *testing.T) {
	base := unicodeBase(t)
	for _, tc := range []struct{ root, p string }{
		{nfdName, nfcName}, // root recorded NFD (tab completion), Claude's NFC cwd
		{nfcName, nfdName}, // root typed NFC, Codex's getcwd (stored NFD)
	} {
		c := config.Config{Roots: []config.Root{{ID: "0123456789abcdef0123456789abcdef", Path: filepath.Join(base, tc.root)}}}
		for _, p := range []string{filepath.Join(base, tc.p), filepath.Join(base, tc.p, "sub")} {
			if _, ok := c.RootFor(p); !ok {
				t.Errorf("root %q does not contain %q", tc.root, p)
			}
		}
		if _, ok := c.RootFor(filepath.Join(base, "other")); ok {
			t.Error("an unrelated path matched")
		}
	}
}

// D93: roots.list carries the spelling the file system stores next to
// the configured one, for the byte-comparing shim.
func TestRootsListCarriesTheStoredSpelling(t *testing.T) {
	base := unicodeBase(t)
	c := config.Default()
	c.Roots = []config.Root{{ID: "0123456789abcdef0123456789abcdef", Path: filepath.Join(base, nfcName), MD: config.MDLedger}}
	list := filepath.Join(t.TempDir(), "roots.list")
	if err := config.WriteRootsList(list, c); err != nil {
		t.Fatal(err)
	}
	got, err := config.ReadRootsList(list)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, filepath.Join(base, nfcName)) || !slices.Contains(got, filepath.Join(base, nfdName)) {
		t.Fatalf("roots.list %q lacks a spelling", got)
	}
}
