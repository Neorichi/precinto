package main

import (
	"errors"
	"syscall"
	"testing"

	"github.com/Neorichi/precinto/internal/fsx/failpoint"
	"github.com/Neorichi/precinto/internal/paths"
)

// main arms PRECINTO_CRASHPOINT through internal/paths in -tags failpoints
// builds only (TESTPLAN §4); every other build ignores the variable (and
// failpoint.Set, which panics there, is never called).
func TestArmFailpoints(t *testing.T) {
	t.Setenv(paths.EnvCrashpoint, "cmdprecinto.test=errno:EIO")
	defer failpoint.Reset()
	armFailpoints() // must not panic in any build
	err := failpoint.Hit("cmdprecinto.test")
	if !failpoint.Enabled() {
		if err != nil {
			t.Fatalf("a non-failpoints build armed a fault: %v", err)
		}
		return
	}
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("failpoints build: Hit = %v, want EIO from PRECINTO_CRASHPOINT", err)
	}
}
