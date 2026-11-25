package claude

// Test-only access to the adapter's seams (compiled into the test binary
// only; the external tests in package claude_test use it).

import (
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// StandInForWSL makes the adapter's WSL checks (D156) answer with drive
// (paths.CheckDrive) and program (harness.CheckProgram) until restore is
// called.
func StandInForWSL(drive func(string) error, program func(paths.Env, harness.ID, string) error) (restore func()) {
	oldDrive, oldProgram := checkDrive, checkProgram
	checkDrive, checkProgram = drive, program
	return func() { checkDrive, checkProgram = oldDrive, oldProgram }
}
