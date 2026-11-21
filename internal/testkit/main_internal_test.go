package testkit

import (
	"os"
	"testing"
)

// TestMain removes the binaries the self-tests built (BuildBinary), so the
// package leaves nothing in TMPDIR.
func TestMain(m *testing.M) {
	code := m.Run()
	removeBinaries()
	os.Exit(code)
}
