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
