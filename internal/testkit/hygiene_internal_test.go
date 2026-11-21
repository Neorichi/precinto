package testkit

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestScanFileWindows: matches beyond the first window, ending past the
// window limit, or starting in the shared overlap are each reported once,
// with the right line.
func TestScanFileWindows(t *testing.T) {
	var b bytes.Buffer
	line := strings.Repeat("x", 99) + "\n"
	put := func(at int, s string) int { // writes " "+s so that s starts at offset at
		for b.Len()+len(line) <= at-1 {
			b.WriteString(line)
		}
		b.WriteString(strings.Repeat("y", at-1-b.Len()) + " ")
		l := 1 + bytes.Count(b.Bytes(), []byte("\n"))
		b.WriteString(s + "\n")
		return l
	}
	want := map[int]bool{
		put(scanWindow-5, "/Users/across/x"):        true, // ends past the limit
		put(scanWindow+100, "/Users/overlap/x"):     true, // inside the overlap
		put(3*scanWindow+scanOverlap, "/home/late"): true,
	}
	p := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &hygieneScanner{}
	got := map[int]int{}
	if err := s.scanFile(p, func(l int, kind string) { got[l]++ }); err != nil {
		t.Fatal(err)
	}
	for l := range want {
		if got[l] != 1 {
			t.Errorf("line %d reported %d times (all: %v)", l, got[l], got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("reported lines %v, want %v", got, want)
	}
}

func TestRealHomeRule(t *testing.T) {
	s := &hygieneScanner{realHome: regexp.MustCompile(boundary + "(" + regexp.QuoteMeta("/opt/ci/home") + `)(?:$|[^A-Za-z0-9._~-])`)}
	var kinds []string
	for _, in := range []string{"x /opt/ci/home/.claude y", "/opt/ci/home", "/opt/ci/homework", "/opt/ci/home-other"} {
		b := []byte(in)
		s.scanBytes(b, len(b), func(_ int, kind string) { kinds = append(kinds, in+"="+kind) })
	}
	if strings.Join(kinds, ",") != "x /opt/ci/home/.claude y=real HOME path,/opt/ci/home=real HOME path" {
		t.Errorf("real HOME findings: %q", kinds)
	}
	// Allowed temp roots win over every path rule.
	s = &hygieneScanner{allowRoots: []string{"/home/runner/tmp"}, allowSlugs: []string{claudeSlug("/home/runner/tmp")}}
	for _, in := range []string{"/home/runner/tmp/TestX/001/home/work", "-home-runner-tmp-TestX-001-home-work"} {
		b := []byte(in)
		s.scanBytes(b, len(b), func(_ int, kind string) { t.Errorf("%q flagged as %s inside the temp root", in, kind) })
	}
	b := []byte("/home/runner/work/x")
	n := 0
	s.scanBytes(b, len(b), func(int, string) { n++ })
	if n != 1 {
		t.Errorf("path outside the temp root: %d findings", n)
	}
}

func TestIsFixtureUUID(t *testing.T) {
	for u, want := range map[string]bool{
		"11111111-2222-3333-4444-555555555555": true,
		"00000000-0000-0000-0000-000000000000": true,
		"ffffffff-ffff-ffff-ffff-ffffffffffff": true,
		"00000000-0000-4000-8000-000000000001": true,
		"00000000-0000-0000-0000-00000000beef": true,
		"6ba7b811-9dad-11d1-80b4-00c04fd430c8": true,
		"6BA7B810-9DAD-11D1-80B4-00C04FD430C8": true,
		"11111111-2222-3333-4444-555555555556": false,
		"00000000-0000-4001-8000-000000000001": false,
		"00000001-0000-0000-0000-000000000000": false,
		"3f1c9a7e-5b2d-4e8f-9a6c-1d2e3f4a5b6c": false,
		"not-a-uuid":                           false,
	} {
		if got := isFixtureUUID(u); got != want {
			t.Errorf("isFixtureUUID(%q) = %v, want %v", u, got, want)
		}
	}
}

// TestScanFileWindowContext is a regression test: a match at a window
// boundary is decided with the bytes before the window, as in a whole-file
// scan. Before the fix, a secret whose keyword ended one window and whose
// value began the next was missed, and a path continuing a word across the
// boundary ("x/Users/…") was flagged because the next window began at it.
// Small windows keep the test fast; TestScanFileWindows covers the real
// geometry.
func TestScanFileWindowContext(t *testing.T) {
	const window, overlap = 4096, 256
	value := strings.Repeat("Zq9xK2mP", 3) // letters and digits, no placeholder word
	tail := strings.Repeat(" ", overlap+scanContext) + "\n"
	cases := []struct {
		name, body string
		want       []string
	}{
		{"keyword before the boundary, value after it",
			strings.Repeat(" ", window-len("token=")) + "token=" + value + tail, []string{"secret assignment"}},
		{"path continuing a word across the boundary",
			strings.Repeat(" ", window-1) + "x/Users/bob/notes" + tail, nil},
		{"path right after a boundary character",
			strings.Repeat(" ", window-1) + " /Users/bob/notes" + tail, []string{"home directory path"}},
		{"\\b at the window start",
			strings.Repeat(" ", window-1) + "x" + "gh" + "p_" + strings.Repeat("a1B2", 10) + tail, nil},
		{"keyword ending where the third window's responsibility starts",
			strings.Repeat(" ", 2*window-scanContext-len("password=")) + "password=" + value + tail, []string{"secret assignment"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "window.txt")
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			s := &hygieneScanner{window: window, overlap: overlap}
			var got []string
			if err := s.scanFile(p, func(l int, kind string) {
				got = append(got, kind)
				if l != 1 {
					t.Errorf("finding on line %d, want 1", l)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("findings %v, want %v", got, c.want)
			}
			// The whole-file scan agrees.
			var whole []string
			s.scanBytes([]byte(c.body), len(c.body), func(_ int, kind string) { whole = append(whole, kind) })
			if strings.Join(whole, ",") != strings.Join(c.want, ",") {
				t.Errorf("whole-file scan %v, want %v", whole, c.want)
			}
		})
	}
}
