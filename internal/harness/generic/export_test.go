package generic

// Test-only access to the adapter's seams (compiled into the test binary
// only; the external tests in package generic_test use it).

import (
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// StandInForWSL makes the WSL program check (D156) answer with program
// until restore is called. Tests that use it never run in parallel.
func StandInForWSL(program func(paths.Env, harness.ID, string) error) (restore func()) {
	old := checkProgram
	checkProgram = program
	return func() { checkProgram = old }
}
