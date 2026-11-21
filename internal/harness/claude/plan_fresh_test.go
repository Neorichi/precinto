package claude_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// uuid4RE is a canonical lower-case version-4 UUID.
var uuid4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// UX-02, D107: a fresh Claude launch in a protected folder starts a
// session whose id precinto knows before exec — the one the user named,
// else a new random one passed with --session-id — and names it in
// LaunchPlan.SessionID for the wrapper to record, without narrowing the
// seal after exit to it (its scope stays every session the child owns);
// launches that start no session here (subcommands, background agents,
// cloud sessions, resumes) get none.
func TestPlanLaunchChoosesTheSessionIDOfAFreshLaunch(t *testing.T) {
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

	// Chosen here: interactive, print mode, --bare (no hooks at all), a
	// prompt, an option value that is no subcommand.
	seen := map[string]bool{}
	for _, args := range [][]string{
		{"claude"},
		{"claude", "-p", "hello"},
		{"claude", "--bare"},
		{"claude", "fix the build"},
		{"claude", "--model", "opus", "--add-dir", f.h.Root},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, args)
		if err != nil {
			t.Fatal(err)
		}
		if !uuid4RE.MatchString(plan.SessionID) {
			t.Fatalf("%q: session id %q, want a new v4 session id", args, plan.SessionID)
		}
		if len(plan.SealScope.SIDs) != 0 || !slices.Equal(plan.SealScope.RootIDs, []string{"root-acme"}) {
			t.Fatalf("%q: seal scope %+v, want the folder's sessions of the child, no session named", args, plan.SealScope)
		}
		sid := plan.SessionID
		i := slices.Index(plan.Argv, "--session-id")
		if i < 1 || i+1 >= len(plan.Argv) || plan.Argv[i+1] != sid {
			t.Fatalf("%q: argv %q does not pass the session id %s", args, plan.Argv, sid)
		}
		// Injected ahead of the user's own arguments, after precinto's
		// settings: everything the user typed follows unchanged.
		if !slices.Equal(plan.Argv[i+2:], args[1:]) {
			t.Fatalf("%q: argv %q, want the user's arguments after the id", args, plan.Argv)
		}
		if seen[sid] {
			t.Fatalf("session id %s chosen twice", sid)
		}
		seen[sid] = true
	}

	// The user's own --session-id is kept as given and is the session id.
	const mine = "1A2B3C4D-0000-4000-8000-00000000BEEF"
	for _, args := range [][]string{
		{"claude", "--session-id", mine},
		{"claude", "--session-id=" + mine, "-p", "hi"},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, args)
		if err != nil {
			t.Fatal(err)
		}
		if plan.SessionID != "1a2b3c4d-0000-4000-8000-00000000beef" || len(plan.SealScope.SIDs) != 0 {
			t.Errorf("%q: session id %q seal scope %+v, want the user's id and no session named", args, plan.SessionID, plan.SealScope)
		}
		if n := countOf(plan.Argv, "--session-id") + countPrefix(plan.Argv, "--session-id="); n != 1 {
			t.Errorf("%q: argv %q passes %d session ids", args, plan.Argv, n)
		}
	}

	// No new local session here: no id chosen, nothing injected.
	for _, args := range [][]string{
		{"claude", "--session-id", "not-a-uuid"},
		{"claude", "logs", "7c5dcf5d"},
		{"claude", "stop", "7c5dcf5d"},
		{"claude", "agents"},
		{"claude", "auth", "status"},
		{"claude", "--bg", "run the tests"},
		{"claude", "--background", "x"},
		{"claude", "--teleport"},
		{"claude", "--from-pr", "123"},
		{"claude", "--cloud", "fix it"},
		{"claude", "--desktop"},
		{"claude", "-p", "--no-session-persistence", "hi"},
		{"claude", "--init-only"},
		{"claude", "-c"},
		{"claude", "--resume"},
		{"claude", "--resume", sid1},
		{"claude", "--resume", sid1, "--fork-session"},
	} {
		plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, args)
		if err != nil {
			t.Fatal(err)
		}
		if countOf(plan.Argv, "--session-id") != countOf(args, "--session-id") || plan.SessionID != "" {
			t.Errorf("%q: argv %q session id %q, want no --session-id added", args, plan.Argv, plan.SessionID)
		}
		if len(args) == 3 && args[1] == "--resume" && args[2] == sid1 {
			continue // a resume's scope is its target (CC-21)
		}
		if len(plan.SealScope.SIDs) != 0 {
			t.Errorf("%q: seal scope %+v, want no session id", args, plan.SealScope)
		}
	}

	// Outside every folder the launch is unmanaged: nothing is injected.
	plan, err := f.a.PlanLaunch(ctx, f.e, filepath.Join(f.h.HomeDir, "elsewhere"), []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(plan.Argv, "--session-id") || len(plan.SealScope.SIDs) != 0 || plan.SessionID != "" {
		t.Errorf("unmanaged launch: argv %q scope %+v session id %q", plan.Argv, plan.SealScope, plan.SessionID)
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}

func countPrefix(list []string, p string) int {
	n := 0
	for _, v := range list {
		if len(v) > len(p) && v[:len(p)] == p {
			n++
		}
	}
	return n
}
