package codex_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/codex"
	"github.com/Neorichi/precinto/internal/harness/codex/codextest"
	"github.com/Neorichi/precinto/internal/paths"
)

func onDrives(dirs ...string) func(string) error {
	return func(p string) error {
		for _, d := range dirs {
			if paths.Within(d, p) {
				return &paths.DriveError{Path: p}
			}
		}
		return nil
	}
}

func noProgram(paths.Env, harness.ID, string) error { return nil }

// D156: under WSL neither a folder's sealed Codex home nor the Codex home
// it is seeded from may be on a Windows drive (a CODEX_HOME shared with a
// Windows Codex); nothing is created or linked then.
func TestPrepareHomeRefusesWindowsDrives(t *testing.T) {
	user, home := seedFixture(t)
	ctx := context.Background()
	restore := codex.StandInForWSL(onDrives(user), noProgram)
	defer func() { restore() }() // the last stand-in's
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); !errors.Is(err, paths.ErrWindowsDrive) {
		t.Fatalf("user home on a drive: %v", err)
	}
	if _, err := os.Lstat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the sealed home was created: %v", err)
	}
	restore()
	restore = codex.StandInForWSL(onDrives(filepath.Dir(home)), noProgram)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); !errors.Is(err, paths.ErrWindowsDrive) {
		t.Fatalf("sealed home on a drive: %v", err)
	}
	restore()
	restore = codex.StandInForWSL(onDrives(), noProgram)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatalf("both on Linux: %v", err)
	}
}

// D156: under WSL a launch refuses a Codex that would run as a Windows
// program, and a managed launch refuses a Codex home on a Windows drive.
func TestPlanLaunchCodexUnderWSL(t *testing.T) {
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "codex")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700)
	hc := f.e.Cfg.Harness["codex"]
	hc.Bin = bin
	f.e.Cfg.Harness["codex"] = hc
	codextest.New(t, f.h.CodexUser, codextest.Options{})
	ctx := context.Background()

	restore := codex.StandInForWSL(onDrives(), func(_ paths.Env, h harness.ID, exe string) error {
		return &harness.ProgramError{Harness: h, Exe: exe, Why: "is on a Windows drive"}
	})
	_, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"})
	var pe *harness.ProgramError
	if !errors.As(err, &pe) || pe.Harness != harness.Codex || pe.Exe != bin {
		t.Fatalf("Windows program: %v", err)
	}
	restore()
	restore = codex.StandInForWSL(onDrives(f.h.CodexUser), noProgram)
	defer restore()
	if _, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"}); !errors.Is(err, paths.ErrWindowsDrive) {
		t.Fatalf("user home on a drive: %v", err)
	}
	// Outside every folder Codex runs on the user's own home, unmanaged.
	if _, err := f.a.PlanLaunch(ctx, f.e, f.h.HomeDir, []string{"codex"}); err != nil {
		t.Fatalf("unmanaged launch: %v", err)
	}
}
