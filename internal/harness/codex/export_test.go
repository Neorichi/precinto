package codex

import (
	"testing"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/paths"
)

// GoldenTrust exposes the pinned Codex 0.154 trust hashes of precinto's
// hooks ("<event label>:<group>:<handler>" → hash) to the external tests.
func GoldenTrust(t *testing.T) map[string]string { return goldenTrust(t) }

// AuthRecordName is the per-root home's auth.json sync record (D100).
const AuthRecordName = authRecordName

// StandInForWSL makes the adapter's WSL checks (D156) answer with drive
// (paths.CheckDrive) and program (harness.CheckProgram) until restore is
// called. Tests that use it never run in parallel.
func StandInForWSL(drive func(string) error, program func(paths.Env, harness.ID, string) error) (restore func()) {
	oldDrive, oldProgram := checkDrive, checkProgram
	checkDrive, checkProgram = drive, program
	return func() { checkDrive, checkProgram = oldDrive, oldProgram }
}
