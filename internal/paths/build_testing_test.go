//go:build testing

package paths_test

import (
	"testing"

	"github.com/precinto/precinto/internal/paths"
)

// TestTestingBuild: -tags testing builds honour the overrides even in an
// agent context (D6).
func TestTestingBuild(t *testing.T) {
	if !paths.TestingBuild() {
		t.Fatal("TestingBuild() = false in a -tags testing build")
	}
	e := paths.FromMap(map[string]string{"HOME": "/u", paths.EnvClaudeCode: "1", paths.EnvHome: "/b", paths.EnvRuntimeDir: "/r"})
	if !paths.OverridesAllowed(e) {
		t.Fatal("testing build refuses overrides")
	}
	if l, err := paths.NewLayout(e); err != nil || l.Base != "/b" || l.RunDir != "/r" {
		t.Fatalf("NewLayout = %+v, %v", l, err)
	}
}

// Testing builds read PRECINTO_TEST_ANCESTRY_STOP and accept only PID:START.
func TestTestingAncestryStop(t *testing.T) {
	for v, want := range map[string]bool{
		"123:456": true, "1:0": true, "": false, "123": false, ":456": false, "123:": false,
		"0:5": false, "-1:5": false, "12:3x": false, " 12:3": false, "12:3:4": false,
	} {
		got, ok := paths.TestAncestryStop(paths.FromMap(map[string]string{paths.EnvTestAncestryStop: v}))
		if ok != want || (ok && got != v) {
			t.Errorf("TestAncestryStop(%q) = %q %v, want ok=%v", v, got, ok, want)
		}
	}
	if _, ok := paths.TestAncestryStop(paths.FromMap(nil)); ok {
		t.Error("unset variable reported")
	}
}
