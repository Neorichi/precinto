package claude_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/paths"
)

// onDrives is a stand-in for paths.CheckDrive under WSL: the listed
// folders are Windows drives.
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

// D156: under WSL a Claude home whose config folder is on a Windows drive
// is never scanned (nothing of it is sealed); a tmp or cache folder there
// leaves the home.
func TestHomesOnWindowsDrives(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	ctx := context.Background()
	hasHome := func() (harness.Home, bool) {
		hs, err := f.a.Homes(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hs {
			if h.Bases[capsule.BaseClaudeConfig] == f.h.ClaudeConfig {
				return h, true
			}
		}
		return harness.Home{}, false
	}
	if h, ok := hasHome(); !ok || h.Bases[capsule.BaseClaudeTmp] == "" {
		t.Fatalf("home outside WSL: %+v %v", h, ok)
	}
	restore := claude.StandInForWSL(onDrives(f.h.ClaudeTmp), noProgram)
	h, ok := hasHome()
	if !ok || h.Bases[capsule.BaseClaudeTmp] != "" || h.Bases[capsule.BaseClaudeCache] == "" {
		t.Fatalf("tmp on a drive: %+v %v", h, ok)
	}
	restore()
	restore = claude.StandInForWSL(onDrives(f.h.ClaudeConfig), noProgram)
	defer restore()
	if _, ok := hasHome(); ok {
		t.Fatal("a home on a Windows drive is still scanned")
	}
	units, err := f.a.Scan(ctx, f.e, harness.Scope{Adopt: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range units {
		if u.Home.Bases[capsule.BaseClaudeConfig] == f.h.ClaudeConfig {
			t.Fatalf("unit of a home on a Windows drive: %+v", u.Ref())
		}
	}
}

// D156: nothing is restored into a registered home on a Windows drive, and
// a tmp folder there is skipped with its reason.
func TestTargetsOnWindowsDrives(t *testing.T) {
	f := newFx(t)
	f.session(sid1, f.h.Root, nil)
	u := sessionUnit(t, f, sid1)
	ctx := context.Background()
	restore := claude.StandInForWSL(onDrives(f.h.ClaudeTmp), noProgram)
	if err := os.Chmod(f.h.ClaudeTmp, 0o700); err != nil {
		t.Fatal(err)
	}
	rules, err := f.a.Targets(ctx, f.e, u.Ref(), sid1)
	if err != nil || rules.Skip[capsule.BaseClaudeTmp] != "on a Windows drive" {
		t.Fatalf("tmp on a drive: %+v %v", rules.Skip, err)
	}
	restore()
	restore = claude.StandInForWSL(onDrives(f.h.ClaudeConfig), noProgram)
	defer restore()
	if _, err := f.a.Targets(ctx, f.e, u.Ref(), sid1); !errors.Is(err, paths.ErrWindowsDrive) {
		t.Fatalf("config on a drive: %v", err)
	}
}

// D156: under WSL a launch refuses a Claude that would run as a Windows
// program, and a managed launch refuses a home on a Windows drive.
func TestPlanLaunchUnderWSL(t *testing.T) {
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "claude")
	write(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	hc := f.e.Cfg.Harness["claude-code"]
	hc.Bin = bin
	f.e.Cfg.Harness["claude-code"] = hc
	ctx := context.Background()

	var asked []string
	restore := claude.StandInForWSL(onDrives(), func(_ paths.Env, h harness.ID, exe string) error {
		asked = append(asked, exe)
		return &harness.ProgramError{Harness: h, Exe: exe, Why: "is a Windows executable"}
	})
	_, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude"})
	var pe *harness.ProgramError
	if !errors.As(err, &pe) || pe.Harness != harness.ClaudeCode || pe.Exe != bin || len(asked) != 1 {
		t.Fatalf("Windows program: %v, asked %v", err, asked)
	}
	restore()

	restore = claude.StandInForWSL(onDrives(f.h.ClaudeConfig), noProgram)
	defer restore()
	if _, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude"}); !errors.Is(err, paths.ErrWindowsDrive) {
		t.Fatalf("home on a drive, managed launch: %v", err)
	}
	// Outside every folder precinto manages nothing: no home check.
	if _, err := f.a.PlanLaunch(ctx, f.e, f.h.HomeDir, []string{"claude"}); err != nil {
		t.Fatalf("unmanaged launch: %v", err)
	}
}

// D156 item 9: Claude Code's temporary folder off darwin is os.tmpdir()
// (TMPDIR, TMP, TEMP, else /tmp) plus claude-<uid>; /tmp on darwin.
func TestTmpBase(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		goos string
		want string
	}{
		{nil, "linux", "/tmp/claude-1000"},
		{map[string]string{"TMPDIR": "/run/user/1000/tmp/"}, "linux", "/run/user/1000/tmp/claude-1000"},
		{map[string]string{"TMP": "/var/tmp"}, "linux", "/var/tmp/claude-1000"},
		{map[string]string{"TEMP": "/scratch"}, "linux", "/scratch/claude-1000"},
		{map[string]string{"TMPDIR": "", "TMP": "/var/tmp"}, "linux", "/var/tmp/claude-1000"},
		{map[string]string{"TMPDIR": "/a", "TMP": "/b"}, "linux", "/a/claude-1000"},
		{map[string]string{"TMPDIR": "relative/tmp"}, "linux", ""},
		{map[string]string{"TMPDIR": "/"}, "linux", "/claude-1000"},
		{map[string]string{"TMPDIR": "/var/folders/x/T/"}, "darwin", "/private/tmp/claude-1000"},
	} {
		if got := claude.TmpBase(paths.FromMap(c.env), c.goos, 1000); got != c.want {
			t.Errorf("TmpBase(%v, %s) = %q, want %q", c.env, c.goos, got, c.want)
		}
	}
}
