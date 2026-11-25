//go:build darwin || linux

package wrapper_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/wrapper"
)

// UX-02, UX-06, D108: the lines after exit say "sealed" only when the seal
// summary counts sealed files, C9.claude is printed only for a managed
// session whose hooks did not run (an unmanaged session leaves no ledger
// trace, so its hooks are never "seen"), and a hookless session of which
// nothing was found names the command that seals it.
func TestRunExitLinesFollowTheSealSummary(t *testing.T) {
	bins := helpers(t)
	noHooks := ui.Format(ui.MsgClaudeNoHooks, ui.Vars{})
	none := ui.Format(ui.MsgSealNone, ui.Vars{Command: "precinto seal --adopt --root " + acmeFolder})
	const sid = "00000000-0000-4000-8000-0000000000d1"
	okLine := ui.Format(ui.MsgSealedOK, ui.Vars{SID: sid, Files: 2, Bytes: 300, Folder: acmeFolder, Idle: config.Default().Policy.IdleSoft.D()})
	for _, tc := range []struct {
		name      string
		unmanaged bool
		hooks     bool
		seal      wrapper.SealSummary
		want      []string
		never     []string
	}{
		{name: "unmanaged without hooks", unmanaged: true, never: []string{noHooks, none, "sealed"}},
		{name: "hookless and nothing sealed", want: []string{noHooks, none}, never: []string{"sealed this session", "sealed now"}},
		{name: "hookless and sealed", seal: wrapper.SealSummary{SID: sid, Files: 2, Bytes: 300},
			want: []string{noHooks, okLine}, never: []string{none, "sealed now"}},
		{name: "hooks ran and nothing sealed", hooks: true, never: []string{noHooks, none, "sealed"}},
		{name: "a known session with no file sealed", seal: wrapper.SealSummary{SID: sid}, hooks: true,
			never: []string{"sealed this session"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := managedPlan(harness.ClaudeCode, bins.child()...)
			if tc.unmanaged {
				plan.Roots = nil
			}
			b := newFakeBackend(plan)
			b.hooksSeen = tc.hooks
			b.seal = tc.seal
			r := startRunRig(t, b, nil)
			if !tc.unmanaged {
				b.waitRegistered(t)
			}
			r.term.typeKeys("q")
			r.finish()
			got := r.stderr.String()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("stderr %q lacks %q", got, w)
				}
			}
			for _, w := range tc.never {
				if strings.Contains(got, w) {
					t.Errorf("stderr %q has %q", got, w)
				}
			}
			if tc.unmanaged && (b.called("HooksSeen") || b.called("WatchSessions")) {
				t.Errorf("an unmanaged launch asked for hooks or watched sessions: %v", b.callList())
			}
		})
	}
}

// D107: a managed launch follows the child's sessions from its start
// until it was reaped, and the watch has returned before the seal after
// exit runs (so the sessions it recorded are in the seal's scope).
func TestRunWatchesTheChildsSessionsUntilItExits(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan(harness.ClaudeCode, bins.child()...))
	watched := make(chan platform.ProcID, 1)
	b.watch = func(ctx context.Context, child platform.ProcID) {
		watched <- child
		<-ctx.Done()
		b.record("WatchDone")
	}
	r := startRunRig(t, b, nil)
	child := b.waitLaunched(t)
	if got := <-watched; got != child {
		t.Fatalf("watched %+v, launched %+v", got, child)
	}
	r.term.typeKeys("q")
	r.finish()
	calls := strings.Join(b.callList(), ",")
	if i, j := strings.Index(calls, "WatchDone"), strings.Index(calls, "SealAfterExit"); i < 0 || j < 0 || i > j {
		t.Fatalf("calls %s: the watch must end before SealAfterExit", calls)
	}
}

// D108, D112: Ctrl-D on a lock screen shown for a lost subscription ends
// the session with that reason, and the lock screen's ending line makes
// no claim about sealing.
func TestRunCtrlDAfterALossNamesTheLoss(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.child()...))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, Reason: string(ui.ReasonManual)})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	b.failDials(ipc.ErrNoDaemon) // the redials fail: the screen stays the loss's
	b.srv.dropSubscriptions()
	r.term.waitFor(ui.ReasonText(ui.ReasonAgent, 0), m)
	r.term.typeKeys("\x04")
	r.term.waitFor(ui.Format(ui.MsgOverlayEnding, ui.Vars{}), m)
	if strings.Contains(ui.Format(ui.MsgOverlayEnding, ui.Vars{}), "sealed") {
		t.Fatal("C4.ending claims a seal before it happened")
	}
	r.finish()
	want := "locked " + acmeFolder + " (" + ui.ReasonText(ui.ReasonAgent, 0) + ") and ended 1 session(s)."
	if got := r.stderr.String(); !strings.Contains(got, want) {
		t.Fatalf("stderr %q lacks %q", got, want)
	}
}

// D107: C5's resume hint names the session the seal summary names — the
// one the child ran last that the seal found files of (after a /clear, not
// the launch's own target) — and falls back to continuing the folder's
// latest session when the summary names none (a fresh session that wrote
// nothing, which claude --resume could not find).
func TestRunResumeHintNamesTheSessionTheChildRanLast(t *testing.T) {
	bins := helpers(t)
	const target, cleared = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000a2"
	for _, tc := range []struct {
		name   string
		resume harness.Resume
		seal   wrapper.SealSummary
		want   string
		never  string
	}{
		{name: "fresh, cleared", seal: wrapper.SealSummary{SID: cleared, Files: 2, Bytes: 10}, want: "claude --resume " + cleared},
		{name: "fresh, nothing written", want: "claude --continue", never: "claude --resume"},
		{name: "resumed, then cleared", resume: harness.Resume{Kind: harness.ResumeSID, Value: target},
			seal: wrapper.SealSummary{SID: cleared, Files: 1, Bytes: 5}, want: "claude --resume " + cleared, never: target},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := managedPlan(harness.ClaudeCode, bins.child()...)
			plan.Resume = tc.resume
			b := newFakeBackend(plan)
			b.seal = tc.seal
			r := startRunRig(t, b, nil)
			b.waitRegistered(t)
			m := r.term.mark()
			b.srv.publish(ipc.Event{Kind: ipc.EventLocked, Reason: string(ui.ReasonManual)})
			r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
			r.term.typeKeys("\x04")
			r.finish()
			got := r.stderr.String()
			c5 := ui.Format(ui.MsgEnded, ui.Vars{Folder: acmeFolder, N: 1, Reason: ui.ReasonManual, Resume: tc.want})
			if !strings.Contains(got, c5) {
				t.Fatalf("stderr %q lacks C5 %q", got, c5)
			}
			if tc.never != "" && strings.Contains(got, tc.never) {
				t.Fatalf("stderr %q names %q", got, tc.never)
			}
			if tc.seal.Files > 0 {
				sealed := ui.Format(ui.MsgSealedLocked, ui.Vars{SID: tc.seal.SID, Files: tc.seal.Files, Bytes: tc.seal.Bytes})
				if !strings.Contains(got, sealed) {
					t.Fatalf("stderr %q lacks %q", got, sealed)
				}
			}
		})
	}
}

// D108: hook presence is read before the seal after exit. A seal that
// removes the session's files moves its ledger, hooks_seen included, into
// the capsule (S13), so asked afterwards every hooked session that was
// sealed looked hookless and got C9.claude ("hooks didn't run").
func TestRunAsksForHooksBeforeTheSeal(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan(harness.ClaudeCode, bins.child()...))
	b.sealArchives = true
	b.seal = wrapper.SealSummary{SID: "00000000-0000-4000-8000-0000000000d2", Files: 2, Bytes: 300}
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	r.term.typeKeys("q")
	r.finish()
	if got := r.stderr.String(); strings.Contains(got, ui.Format(ui.MsgClaudeNoHooks, ui.Vars{})) || !strings.Contains(got, "precinto: sealed this session (") {
		t.Fatalf("stderr %q: a hooked session that was sealed got C9.claude", got)
	}
	calls := strings.Join(b.callList(), ",")
	if i, j := strings.Index(calls, "HooksSeen"), strings.Index(calls, "SealAfterExit"); i < 0 || j < 0 || i > j {
		t.Fatalf("calls %s: HooksSeen must be asked before SealAfterExit", calls)
	}
}

// D113: C6.none names the folder as one shell word, so its command can be
// pasted as is whatever the folder is called.
func TestRunSealNoneQuotesTheFolder(t *testing.T) {
	bins := helpers(t)
	plan := managedPlan(harness.ClaudeCode, bins.child()...)
	plan.Roots[0].Path = "/nonexistent/fixture/My Work/it's"
	b := newFakeBackend(plan)
	b.hooksSeen = false
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	r.term.typeKeys("q")
	r.finish()
	want := `seal it with: precinto seal --adopt --root '/nonexistent/fixture/My Work/it'\''s'` + "\n"
	if got := r.stderr.String(); !strings.HasSuffix(got, want) {
		t.Fatalf("stderr %q, want it to end with %q", got, want)
	}
}
