package generic_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/generic"
	"github.com/precinto/precinto/internal/paths"
)

// D156: under WSL an experimental harness that would run as a Windows
// program is refused like the built-in ones.
func TestPlanLaunchGenericUnderWSL(t *testing.T) {
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "demo")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700)
	f.e.Host = paths.FromMap(map[string]string{"HOME": f.h.HomeDir, "PATH": filepath.Dir(bin)})
	var asked string
	restore := generic.StandInForWSL(func(_ paths.Env, h harness.ID, exe string) error {
		asked = exe
		return &harness.ProgramError{Harness: h, Exe: exe, Why: "is a Windows executable"}
	})
	defer restore()
	_, err := f.a.PlanLaunch(context.Background(), f.e, f.h.Root, []string{"demo", "run"})
	if !errors.Is(err, harness.ErrWindowsProgram) || asked != bin {
		t.Fatalf("Windows program: %v (asked %q)", err, asked)
	}
}
