package fakeplatform

import (
	"runtime"
	"testing"
)

// TestWithinMatchesPathsWithin pins the copy of paths.Within (this package
// may not import internal/paths) to the cases of internal/paths' own test,
// plus the edges OpenFilesUnder relies on.
func TestWithinMatchesPathsWithin(t *testing.T) {
	for _, c := range []struct {
		root, p string
		want    bool
	}{
		// internal/paths TestWithin
		{"/u/work/acme", "/u/work/acme", true},
		{"/u/work/acme", "/u/work/acme/docs/x.md", true},
		{"/u/work/acme", "/u/work/acme-other/x.md", false}, // never a string prefix
		{"/u/work/acme", "/u/work", false},
		{"/u/work/acme", "/u/work/acme/../beta", false},
		{"/u/work/acme", "work/acme", false},
		{"/", "/anything", true},
		// more edges
		{"/", "/", true},
		{"/u/work/acme/", "/u/work/acme/x", true},
		{"/u//work/./acme", "/u/work/acme/x/", true},
		{"/u/work/acme", "/u/work/acme/x/../..", false},
		{"work/acme", "/u/work/acme", false},
		{"", "/u", false},
		{"/u", "", false},
		{"/u/work/acme", "/u/work/acm", false},
	} {
		if got := within(c.root, c.p); got != c.want {
			t.Errorf("within(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
	darwin := runtime.GOOS == "darwin"
	if got := within("/u/Work/Acme", "/u/work/acme/x"); got != darwin {
		t.Errorf("case folding = %v on %s", got, runtime.GOOS)
	}
	if got := within("/u/work/ACME", "/u/work/acmé"); got {
		t.Error("ASCII folding matched a non-ASCII component")
	}
	if !withinAny([]string{"/a", "/u/work"}, "/u/work/acme") || withinAny(nil, "/u") {
		t.Error("withinAny")
	}
}
