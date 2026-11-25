package claude_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/harness"
)

// claudeBin installs a fake claude executable as the configured binary.
func (f *fx) claudeBin() string {
	f.t.Helper()
	bin := filepath.Join(f.h.Dir, "bin", "claude")
	write(f.t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o700); err != nil {
		f.t.Fatal(err)
	}
	hc := f.e.Cfg.Harness["claude-code"]
	hc.Bin = bin
	f.e.Cfg.Harness["claude-code"] = hc
	return bin
}

// D101 (M4): Claude Code 2.1.329 runs `claude daemon …` only when daemon is
// its first argument or follows nothing but --dangerously-skip-permissions
// and --allow-dangerously-skip-permissions (cli-reference; the binary's
// daemon router). In a protected folder those launches are passthrough with
// their argv unchanged: no --settings ahead of daemon, no gate, no restore.
// With any other flag ahead of it Claude starts a session, which precinto
// manages as usual.
func TestPlanLaunchDaemonIsPassthrough(t *testing.T) {
	f := newFx(t)
	bin := f.claudeBin()
	ctx := context.Background()
	for _, args := range [][]string{
		{"daemon", "status"},
		{"daemon", "stop", "--any"},
		{"--dangerously-skip-permissions", "daemon", "status"},
		{"--allow-dangerously-skip-permissions", "daemon", "stop", "--any"},
		{"--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "daemon", "status"},
		{"--allow-dangerously-skip-permissions", "--dangerously-skip-permissions", "daemon", "status"},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, append([]string{"claude"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		if plan.Mode != harness.LaunchPassthrough || !slices.Equal(plan.Argv, append([]string{bin}, args...)) ||
			len(plan.Sync)+len(plan.Background)+len(plan.Env)+len(plan.Lease) != 0 || plan.Confirm != "" {
			t.Errorf("claude %q in a protected folder: mode %s argv %q sync %v env %v confirm %q",
				args, plan.Mode, plan.Argv, plan.Sync, plan.Env, plan.Confirm)
		}
	}
	plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "--verbose", "daemon", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != harness.LaunchInteractive || plan.Argv[1] != "--settings" {
		t.Errorf("another flag ahead of daemon is a session: mode %s argv %q", plan.Mode, plan.Argv)
	}
}

// sessionSelectors returns the claude-session selectors of sels.
func sessionSelectors(sels []harness.Selector) []harness.Selector {
	var out []harness.Selector
	for _, s := range sels {
		if s.Kind == capsule.KindClaudeSession {
			out = append(out, s)
		}
	}
	return out
}

// D102 (M5): Claude Code 2.1.329's interactive --continue skips sessions
// created by claude -p or an Agent SDK, and sessions whose first prompt
// was /loop (cli-reference). `claude -c` therefore restores before exec the
// newest session of the folder it can pick by entrypoint (clamped like an
// explicit resume), the project unit, and then the folder's other recent
// sessions it can pick, unclamped, so the one it picks after a /loop
// session is there too. They come after the project unit: under the
// wrapper's StopOnErr a failure among these best-effort sessions must not
// stop the project unit. claude -p -c picks the newest session of any
// kind: one selector, as before.
func TestPlanLaunchContinueRestoresWhatClaudeCanPick(t *testing.T) {
	f := newFx(t)
	f.claudeBin()
	ctx := context.Background()
	real := realPath(t, f.h.Root)
	for _, args := range [][]string{{"-c"}, {"--continue"}, {"-c", "--fork-session"}} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, append([]string{"claude"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Sync) != 3 || plan.Sync[1].Kind != capsule.KindClaudeProject {
			t.Fatalf("%q: sync before exec %+v, want the newest pickable session, the project unit, then the recent ones", args, plan.Sync)
		}
		first, rest := plan.Sync[0], plan.Sync[2]
		if first.Kind != capsule.KindClaudeSession || !first.Newest || !first.MtimeNow || first.MaxAge != 0 || first.ProjectDir != real ||
			!slices.Equal(first.SkipEntrypoints, []string{"sdk-cli", "sdk-ts", "sdk-py"}) {
			t.Errorf("%q: first selector %+v", args, first)
		}
		if rest.Kind != capsule.KindClaudeSession || rest.Newest || rest.MtimeNow || rest.Recent != 5 || rest.MaxAge != 28*24*time.Hour ||
			rest.ProjectDir != real || !slices.Equal(rest.SkipEntrypoints, first.SkipEntrypoints) {
			t.Errorf("%q: recent selector %+v (unclamped, within retention, the same entrypoints skipped)", args, rest)
		}
	}
	for _, args := range [][]string{{"-p", "-c", "go on"}, {"--print", "--continue"}} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, append([]string{"claude"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		s := sessionSelectors(plan.Sync)
		if len(s) != 1 || !s[0].Newest || len(s[0].SkipEntrypoints) != 0 {
			t.Errorf("%q: sync %+v, want only the newest session of any kind", args, s)
		}
	}
}

// D62: restore_recent = 0 restores no recent session. A selector's Recent 0
// means every match, so with that policy `claude -c` restores only its
// newest pickable session and the project unit, the picker restores only
// the project unit, and nothing follows in the background.
func TestPlanLaunchRestoreRecentZeroAddsNoRecentSelector(t *testing.T) {
	f := newFx(t)
	f.claudeBin()
	f.e.Cfg.Policy.RestoreRecent = 0
	ctx := context.Background()
	for _, args := range [][]string{{"-c"}, {"-r"}, {}} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, append([]string{"claude"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		for _, sel := range append(append([]harness.Selector(nil), plan.Sync...), plan.Background...) {
			if sel.Kind == capsule.KindClaudeSession && !sel.Newest && len(sel.Keys) == 0 && sel.Title == "" {
				t.Errorf("claude %q with restore_recent = 0: recent selector %+v (sync %+v, background %+v)", args, sel, plan.Sync, plan.Background)
			}
		}
		if len(plan.Background) != 0 {
			t.Errorf("claude %q with restore_recent = 0: background %+v", args, plan.Background)
		}
	}
	plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"claude", "-c"})
	if err != nil {
		t.Fatal(err)
	}
	if s := sessionSelectors(plan.Sync); len(s) != 1 || !s[0].Newest {
		t.Errorf("claude -c with restore_recent = 0: sync %+v, want the newest pickable session only", plan.Sync)
	}
}
