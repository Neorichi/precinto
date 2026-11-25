package platform_test

import (
	"testing"

	"github.com/Neorichi/precinto/internal/testkit"
)

// TestFixtureHygiene: the console-tool fixtures are synthetic (no real
// paths, users, emails, tokens or UUIDs, S13).
func TestFixtureHygiene(t *testing.T) { testkit.Hygiene(t, "testdata") }
