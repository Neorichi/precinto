//go:build !testing

package paths_test

import (
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
)

// TestProductionBuild: without -tags testing the overrides need PRECINTO_DEV=1
// and no agent marker (D6, SEC-12).
func TestProductionBuild(t *testing.T) {
	if paths.TestingBuild() {
		t.Fatal("TestingBuild() = true without -tags testing")
	}
	hijack := paths.FromMap(map[string]string{"HOME": "/u", paths.EnvHome: "/b", paths.EnvRuntimeDir: "/r"})
	if paths.OverridesAllowed(hijack) {
		t.Fatal("production build honours PRECINTO_HOME without PRECINTO_DEV")
	}
	if l, err := paths.NewLayout(hijack); err != nil || l.Base == "/b" || l.RunDir == "/r" {
		t.Fatalf("NewLayout = %+v, %v", l, err)
	}
	inHook := hijack.With(paths.EnvDev, "1").With(paths.EnvClaudeProjectDir, "/u/work")
	if paths.OverridesAllowed(inHook) {
		t.Fatal("production build honours PRECINTO_DEV in an agent context")
	}
}

// Production builds never read PRECINTO_TEST_ANCESTRY_STOP (D64, SEC-33).
func TestProductionIgnoresAncestryStop(t *testing.T) {
	e := paths.FromMap(map[string]string{"HOME": "/u", paths.EnvTestAncestryStop: "123:456"})
	if v, ok := paths.TestAncestryStop(e); ok || v != "" {
		t.Fatalf("TestAncestryStop = %q %v in a production build", v, ok)
	}
}
