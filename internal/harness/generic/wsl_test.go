package generic_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/generic"
	"github.com/Neorichi/precinto/internal/paths"
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

// D156: under WSL the home of an experimental harness on a Windows drive
// (~/.gemini shared with a Windows install) is neither scanned, sealed nor
// restored into: Homes, Scan (seal --dormant) and Targets report the
// drive; precinto cannot see the Windows writer. Off the drive all work.
func TestHomeOnAWindowsDrive(t *testing.T) {
	f := newFx(t)
	f.write("sessions/s1.json", "{}")
	ctx := context.Background()
	for _, de := range []*paths.DriveError{{Path: f.home}, {Path: f.home, Unknown: true, Why: "it is a dangling symlink"}} {
		restore := generic.StandInDrivesForWSL(func(p string) error {
			if paths.Within(f.home, p) {
				return de
			}
			return nil
		})
		if _, err := f.a.Homes(ctx, f.e); !errors.Is(err, paths.ErrWindowsDrive) {
			t.Errorf("Homes (unknown %v): %v", de.Unknown, err)
		}
		if units, err := f.a.Scan(ctx, f.e, dormant); !errors.Is(err, paths.ErrWindowsDrive) || len(units) != 0 {
			t.Errorf("Scan (unknown %v): %d units, %v", de.Unknown, len(units), err)
		}
		ref := harness.UnitRef{Harness: f.a.ID(), Kind: capsule.KindGeneric, HomeID: "x"}
		if _, err := f.a.Targets(ctx, f.e, ref, "s1"); !errors.Is(err, paths.ErrWindowsDrive) {
			t.Errorf("Targets (unknown %v): %v", de.Unknown, err)
		}
		restore()
	}
	restore := generic.StandInDrivesForWSL(func(string) error { return nil })
	defer restore()
	if hs, err := f.a.Homes(ctx, f.e); err != nil || len(hs) != 1 {
		t.Fatalf("off the drive: %v, %v", hs, err)
	}
}
