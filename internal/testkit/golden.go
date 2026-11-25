package testkit

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
)

// Golden files are rewritten when the test binary runs with -update
// (`go test ./internal/hook -update`) or with PRECINTO_UPDATE_GOLDEN=1 in the
// environment (`PRECINTO_UPDATE_GOLDEN=1 go test ./...`, which also reaches
// packages whose test binaries have no -update flag). testkit registers
// -update itself, so a test package that imports testkit must not define a
// flag of that name (the flag package panics on a redefinition).
const updateGoldenEnv = "PRECINTO_UPDATE_GOLDEN"

func init() {
	if flag.Lookup("update") == nil {
		flag.Bool("update", false, "rewrite the testdata/ golden files compared by testkit.Golden")
	}
}

// updatingGolden reports whether Golden rewrites instead of comparing.
func updatingGolden() bool {
	if f := flag.Lookup("update"); f != nil {
		if on, err := strconv.ParseBool(f.Value.String()); err == nil && on {
			return true
		}
	}
	return paths.FromOS().Get(updateGoldenEnv) == "1"
}

// golden implements Golden. name is a slash-separated path inside the
// package's testdata/ directory. When rewriting, content that fails the
// hygiene rules is refused (it would fail testkit.Hygiene in CI and may be
// real data, S13); files are written 0644, directories 0755 (they belong to
// the repository).
func golden(t testing.TB, name string, got []byte) {
	t.Helper()
	rel := filepath.FromSlash(name)
	if name == "" || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		t.Fatalf("testkit.Golden: %q is not a clean path inside testdata/", name)
	}
	p := filepath.Join("testdata", rel)
	if updatingGolden() {
		if kinds := hygieneOfBytes(t, got); len(kinds) > 0 {
			t.Errorf("testkit.Golden: refusing to write %s: it fails the hygiene check (%s)", p, strings.Join(kinds, "; "))
			return
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("testkit.Golden: %v", err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatalf("testkit.Golden: %v", err)
		}
		t.Logf("testkit.Golden: updated %s", p)
		return
	}
	want, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("testkit.Golden: %s does not exist (run the test with -update to create it)", p)
		return
	}
	if err != nil {
		t.Errorf("testkit.Golden: %v", err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("testkit.Golden: %s differs (run with -update to accept the new output): %s", p, firstDifference(want, got))
	}
}

// firstDifference describes where got first departs from want.
func firstDifference(want, got []byte) string {
	wl, gl := splitLines(want), splitLines(got)
	for i := 0; i < len(wl) || i < len(gl); i++ {
		switch {
		case i >= len(wl):
			return fmt.Sprintf("line %d: unexpected extra line %s", i+1, clip(gl[i]))
		case i >= len(gl):
			return fmt.Sprintf("line %d: missing line %s", i+1, clip(wl[i]))
		case !bytes.Equal(wl[i], gl[i]):
			return fmt.Sprintf("line %d: want %s, got %s", i+1, clip(wl[i]), clip(gl[i]))
		}
	}
	if bytes.HasSuffix(want, []byte("\n")) != bytes.HasSuffix(got, []byte("\n")) {
		return "only the final newline differs"
	}
	return fmt.Sprintf("%d bytes want, %d bytes got", len(want), len(got))
}

// splitLines splits b into lines, without the empty element a final
// newline leaves.
func splitLines(b []byte) [][]byte {
	lines := bytes.Split(b, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	return lines
}

func clip(b []byte) string {
	const max = 120
	if len(b) > max {
		return strconv.Quote(string(b[:max])) + "…"
	}
	return strconv.Quote(string(b))
}
