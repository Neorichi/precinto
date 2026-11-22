//go:build crossgroup

package claude_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
)

// D132 (D6-3): the units a launch restores beside its target — the
// project unit, the other recent sessions `claude -c` and the picker
// restore — are left as they are when another Claude uses them, and the
// launch goes on (the wrapper refuses a launch whenever RestoreSync
// fails). The launch's own target stays required: live elsewhere, the
// restore fails. The result says what the launch gets: a sealed unit in
// use elsewhere is not restored (the project unit while another Claude
// runs in the folder); one whose plaintext is on disk is left as it is
// (the session another terminal runs).
func TestD132LaunchBesideAnotherClaude(t *testing.T) {
	for _, tc := range []struct {
		name    string
		argv    []string
		inside  bool   // the other Claude's cwd is the folder
		running string // the session the other Claude runs ("": none)
		refused bool
		detail  string // the result of the unit in use elsewhere
	}{
		{"fresh launch, another Claude in the folder", nil, true, "", false, "in use elsewhere: not restored"},
		{"picker, another Claude in the folder", []string{"-r"}, true, "", false, "in use elsewhere: not restored"},
		{"claude -c, another recent session running elsewhere", []string{"-c"}, false, sid1, false, "in use elsewhere: left as it is"},
		{"claude -c, the session it continues running elsewhere", []string{"-c"}, false, sid2, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newXStack(t)
			h := s.h
			continueSessions(t, s, "cli", false) // sid1 (older), sid2 (newer), sealed with the project unit
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			homes, err := claude.New().Homes(ctx, s.env().Harness)
			if err != nil || len(homes) == 0 {
				t.Fatalf("homes %v %v", homes, err)
			}
			pid := 4711
			h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: pid}, Exe: "/usr/local/bin/claude"})
			if tc.inside {
				h.Procs.SetCwd(pid, h.Root)
			} else {
				h.Procs.SetCwd(pid, h.HomeDir)
			}
			if tc.running != "" {
				k, err := harness.UnitKeyFor(s.salt, capsule.KindClaudeSession, harness.ClaudeCode, homes[0].ID, "", tc.running)
				if err != nil {
					t.Fatal(err)
				}
				rep, err := sweep.Restore(ctx, s.env(), s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{{Harness: harness.ClaudeCode,
					Kind: capsule.KindClaudeSession, Key: k}}})
				if err != nil || rep.Count(sweep.OutRestored) != 1 {
					t.Fatalf("restore of the running session: %+v %v", rep, err)
				}
				claudetest.New(t, h.Dir).WriteRegistry(t, pid, tc.running, h.Root, "busy", true)
			}
			rep := restoreBeforeExec(t, s, tc.argv...)
			err = rep.Err()
			if tc.refused {
				if !errors.Is(err, sweep.ErrLive) {
					t.Fatalf("the launch's own target in use elsewhere: %v, want ErrLive (%+v)", err, rep.Units)
				}
				return
			}
			if err != nil {
				t.Fatalf("the launch is refused because another Claude uses a unit beside its target: %v (%+v)", err, rep.Units)
			}
			left := 0
			for _, u := range rep.Units {
				if u.Outcome == sweep.OutLive || u.Outcome == sweep.OutFailed {
					t.Fatalf("unit %+v", u)
				}
				if u.Outcome == sweep.OutSkipped && u.Detail == tc.detail {
					left++
				}
			}
			if left == 0 {
				t.Fatalf("no unit was left in use: %+v", rep.Units)
			}
		})
	}
}
