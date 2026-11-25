package claude_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Neorichi/precinto/internal/harness"
)

// withBin points the fixture's claude at a stub executable.
func withBin(t *testing.T, f *fx) {
	t.Helper()
	bin := filepath.Join(f.h.Dir, "bin", "claude")
	write(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	hc := f.e.Cfg.Harness["claude-code"]
	hc.Bin = bin
	f.e.Cfg.Harness["claude-code"] = hc
}

// D134 (H6-1): precinto reads Claude's options as Claude 2.1.330 does —
// bundled short options ("-pc" is -p -c), a value attached to a short
// option taken as is ("-r<id>" is --resume <id>; "-r=<id>" is --resume
// "=<id>", a title search, since only a long option splits at "="),
// --pool (an alias of --environment) — so it never passes --session-id to
// a launch Claude refuses it for ("--session-id with --continue or
// --resume also needs --fork-session", "--environment cannot be combined
// with --session-id"), and the continue or resume of such a launch is
// restored like the spelled-out one. The user's argv reaches Claude
// unchanged.
func TestPlanLaunchReadsOptionsAsClaudeDoes(t *testing.T) {
	f := newFx(t)
	withBin(t, f)
	ctx := context.Background()
	for _, tc := range []struct {
		args   []string
		resume harness.ResumeKind
		direct bool
	}{
		{[]string{"claude", "-pc", "next step"}, harness.ResumeContinue, true},
		{[]string{"claude", "-cp", "next step"}, harness.ResumeContinue, true},
		{[]string{"claude", "-r" + sid1}, harness.ResumeSID, false},
		{[]string{"claude", "-r=" + sid1}, harness.ResumeName, false},
		{[]string{"claude", "-pr" + sid1, "go on"}, harness.ResumeSID, true},
		{[]string{"claude", "--pool", "ccpool_abc123", "fix it"}, harness.ResumeNone, false},
		{[]string{"claude", "--pool=ccpool_abc123", "fix it"}, harness.ResumeNone, false},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(plan.Argv, "--session-id") || plan.SessionID != "" {
			t.Errorf("%q: argv %q (session id %q): Claude refuses --session-id here", tc.args, plan.Argv, plan.SessionID)
		}
		if plan.Resume.Kind != tc.resume {
			t.Errorf("%q: resume %q, want %q", tc.args, plan.Resume.Kind, tc.resume)
		}
		if tc.resume == harness.ResumeSID && plan.Resume.Value != sid1 {
			t.Errorf("%q: resume target %q, want %s", tc.args, plan.Resume.Value, sid1)
		}
		if tc.resume == harness.ResumeName && (plan.Resume.Value != "="+sid1 || len(plan.SealScope.SIDs) != 0) {
			// Claude searches the titles for "=<id>": no session is the
			// target, so the seal after exit covers the child's sessions.
			t.Errorf("%q: resume %q, seal scope %v; want the name %q and no session scope", tc.args,
				plan.Resume.Value, plan.SealScope.SIDs, "="+sid1)
		}
		if (plan.Mode == harness.LaunchDirect) != tc.direct {
			t.Errorf("%q: mode %q, direct want %v", tc.args, plan.Mode, tc.direct)
		}
		if i := slices.Index(plan.Argv, tc.args[1]); i < 0 || !slices.Equal(plan.Argv[i:], tc.args[1:]) {
			t.Errorf("%q: argv %q, want the user's arguments unchanged", tc.args, plan.Argv)
		}
	}
	// An option Claude's root command does not have, alone or in a bundle:
	// precinto cannot tell what it means, so it passes no session id either.
	for _, args := range [][]string{{"claude", "-px", "hi"}, {"claude", "-x", "hi"}} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, args)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(plan.Argv, "--session-id") || plan.SessionID != "" {
			t.Errorf("%q: argv %q (session id %q)", args, plan.Argv, plan.SessionID)
		}
	}
	// Bundles of options Claude takes with --session-id still get one.
	for _, args := range [][]string{{"claude", "-p", "-d", "hi"}, {"claude", "-pd", "hi"}, {"claude", "-nwork", "hi"}} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, args)
		if err != nil {
			t.Fatal(err)
		}
		if !uuid4RE.MatchString(plan.SessionID) || !slices.Contains(plan.Argv, "--session-id") {
			t.Errorf("%q: session id %q, argv %q: want a new session id", args, plan.SessionID, plan.Argv)
		}
	}
}

// D135 (H6-2): Claude 2.1.330 starts Remote Control only from the first
// position (`remote-control`, alias `rc`; `remote`, `sync` and `bridge`
// take the same path) and refuses a --settings ahead of it, so those
// launches are passthrough, argv unchanged, like `daemon` (D101); so are
// the aliases `plugins` and `upgrade`. `claude config` is no command (a
// prompt): a managed session with precinto's settings and a session id.
func TestPlanLaunchRemoteControlIsPassthrough(t *testing.T) {
	f := newFx(t)
	bin := f.claudeBin()
	ctx := context.Background()
	for _, args := range [][]string{
		{"remote-control"},
		{"remote-control", "--name", "My Project"},
		{"rc"},
		{"rc", "--name", "My Project"},
		{"remote"}, {"sync"}, {"bridge"},
		{"plugins", "list"},
		{"upgrade"},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, append([]string{"claude"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		if plan.Mode != harness.LaunchPassthrough || !slices.Equal(plan.Argv, append([]string{bin}, args...)) ||
			len(plan.Sync)+len(plan.Background)+len(plan.Env)+len(plan.Lease) != 0 || plan.SessionID != "" {
			t.Errorf("claude %q in a protected folder: mode %s argv %q sync %v session %q",
				args, plan.Mode, plan.Argv, plan.Sync, plan.SessionID)
		}
	}
	plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "config"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode == harness.LaunchPassthrough || plan.Argv[1] != "--settings" || !uuid4RE.MatchString(plan.SessionID) {
		t.Errorf("claude config: mode %s argv %q session %q, want a managed session", plan.Mode, plan.Argv, plan.SessionID)
	}
}
