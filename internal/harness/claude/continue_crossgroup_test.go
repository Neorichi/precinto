//go:build crossgroup

package claude_test

// D102 (M5) end to end with G4's sweep and G1's vaults: what `claude -c`
// restores before Claude starts, through the adapter's own plan.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/testkit"
)

// writeLedgerStart appends the start line a SessionStart hook records for
// sid: its source and the process's entrypoint.
func writeLedgerStart(t *testing.T, s *xStack, sid, source, entrypoint string) {
	t.Helper()
	h := s.h
	if err := s.led.Append(ledger.Event{Type: ledger.TypeStart, Harness: "claude-code", SID: sid, Source: source,
		Roots: []string{"root-acme"}, Cwd: h.Root, ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp, Entrypoint: entrypoint}); err != nil {
		t.Fatal(err)
	}
}

// sealAll runs the lock's sweep and requires n Claude sessions sealed.
func sealAll(t *testing.T, s *xStack, n int) *sweep.Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := sweep.Sweep(ctx, s.env(), sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, u := range rep.Units {
		if u.Kind == capsule.KindClaudeSession && u.Outcome == sweep.OutSealed {
			got++
		}
	}
	if got != n {
		t.Fatalf("%d sessions sealed, want %d: %+v", got, n, rep.Units)
	}
	return rep
}

// continueSessions writes two sessions of the folder, the older one
// interactive, the newer one with the given entrypoint and, with loop, a
// first prompt that is /loop; seals them; and returns both transcripts.
func continueSessions(t *testing.T, s *xStack, newerEntrypoint string, loop bool) (older, newer string) {
	t.Helper()
	h := s.h
	l := claudetest.New(t, h.Dir)
	write := func(sid, entrypoint string, age time.Duration) string {
		paths := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Marker: testkit.Marker(t), ModTime: time.Now().Add(-age)})
		writeLedgerStart(t, s, sid, "startup", entrypoint)
		return paths[0]
	}
	older = write(sid1, "cli", 3*time.Hour)
	newer = write(sid2, newerEntrypoint, time.Hour)
	if loop {
		// Claude records a /loop first prompt as a command; precinto never
		// reads it (content), so it cannot skip this session itself.
		b, err := os.ReadFile(newer)
		if err != nil {
			t.Fatal(err)
		}
		first := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000f1","sessionId":"` + sid2 + `","cwd":"` + h.Root +
			`","message":{"role":"user","content":"<command-name>/loop</command-name>\n<command-args>5m check the build</command-args>"}}` + "\n"
		mt := time.Now().Add(-time.Hour)
		if err := os.WriteFile(newer, append([]byte(first), b...), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(newer, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	sealAll(t, s, 2)
	for _, p := range []string{older, newer} {
		if exists(p) {
			t.Fatalf("session not sealed: %s", filepath.Base(p))
		}
	}
	return older, newer
}

// restoreBeforeExec runs what the wrapper restores before exec for argv:
// the adapter's own plan, its Sync selectors in the request the backend's
// RestoreSync sends (cmd/precinto/backend.go: MtimeNow set when a selector
// has it, StopOnErr).
func restoreBeforeExec(t *testing.T, s *xStack, argv ...string) *sweep.Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h := s.h
	bin := filepath.Join(h.Dir, "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	e := s.env()
	hc := e.Harness.Cfg.Harness["claude-code"]
	hc.Bin = bin
	e.Harness.Cfg.Harness["claude-code"] = hc
	plan, err := claude.New().PlanLaunch(ctx, e.Harness, h.Root, append([]string{"claude"}, argv...))
	if err != nil {
		t.Fatal(err)
	}
	mtimeNow := false
	for _, sel := range plan.Sync {
		mtimeNow = mtimeNow || sel.MtimeNow
	}
	rep, err := sweep.Restore(ctx, s.env(), s.keys, sweep.RestoreRequest{Select: plan.Sync, MtimeNow: mtimeNow, StopOnErr: true})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// The newest session of the folder was started by claude -p: Claude's
// interactive --continue skips it, so the older interactive session must
// be there before Claude starts; claude -p -c continues the newest.
func TestCrossContinueRestoresTheSessionClaudePicks(t *testing.T) {
	s := newXStack(t)
	older, newer := continueSessions(t, s, "sdk-cli", false)
	restoreBeforeExec(t, s, "-c")
	if !exists(older) {
		t.Fatal("claude -c: the interactive session Claude continues was not restored before exec")
	}
	if exists(newer) {
		t.Error("claude -c: the claude -p session Claude skips was restored before exec")
	}

	s = newXStack(t)
	_, newer = continueSessions(t, s, "sdk-cli", false)
	restoreBeforeExec(t, s, "-p", "-c", "go on")
	if !exists(newer) {
		t.Fatal("claude -p -c: the newest session was not restored")
	}
}

// The newest session of the folder began with /loop, which precinto cannot
// see: the session Claude's --continue picks instead is restored before
// exec too.
func TestCrossContinueAfterALoopSession(t *testing.T) {
	s := newXStack(t)
	older, newer := continueSessions(t, s, "cli", true)
	restoreBeforeExec(t, s, "-c")
	if !exists(older) || !exists(newer) {
		t.Fatalf("claude -c after a /loop session: older restored %v, newer restored %v", exists(older), exists(newer))
	}
	if fi, err := os.Stat(older); err != nil || time.Since(fi.ModTime()) < 2*time.Hour {
		t.Errorf("the older session's time was not kept (Claude orders --continue by it): %v %v", fi.ModTime(), err)
	}
}

// Days away (D102, D14): every session of the folder is older than a day.
// The newest one Claude can pick is clamped to now − 1 day, which keeps it
// the newest; the others restored with it keep their own mtimes, which
// Claude's --continue orders by (it continues the newest transcript, and
// identical clamped times would have it continue the last one placed).
func TestCrossContinueKeepsClaudesOrderAfterDaysAway(t *testing.T) {
	s := newXStack(t)
	h := s.h
	l := claudetest.New(t, h.Dir)
	day := 24 * time.Hour
	now := time.Now()
	ages := map[string]time.Duration{sid1: 2 * day, sid2: 3 * day, sid3: 4 * day}
	transcripts := map[string]string{}
	for _, sid := range []string{sid1, sid2, sid3} {
		paths := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Marker: testkit.Marker(t), ModTime: now.Add(-ages[sid])})
		transcripts[sid] = paths[0]
		writeLedgerStart(t, s, sid, "startup", "cli")
	}
	sealAll(t, s, 3)
	restoreBeforeExec(t, s, "-c")
	mtime := func(sid string) time.Time {
		t.Helper()
		fi, err := os.Stat(transcripts[sid])
		if err != nil {
			t.Fatalf("%s not restored before exec: %v", sid, err)
		}
		return fi.ModTime()
	}
	if floor := s.clock.Now().Add(-day); mtime(sid1).Before(floor.Add(-time.Second)) {
		t.Errorf("the newest session was not clamped: %v (floor %v)", mtime(sid1), floor)
	}
	for _, sid := range []string{sid2, sid3} {
		if d := mtime(sid).Sub(now.Add(-ages[sid])); d < -time.Second || d > time.Second {
			t.Errorf("%s: mtime %v, want its own %v", sid, mtime(sid), now.Add(-ages[sid]))
		}
	}
	if !mtime(sid1).After(mtime(sid2)) || !mtime(sid2).After(mtime(sid3)) {
		t.Errorf("Claude's --continue order lost: %v %v %v", mtime(sid1), mtime(sid2), mtime(sid3))
	}
}

// An interactive session continued in place by `claude -p -c` (D102): its
// newest generation's ledger holds only the sdk-cli resume, yet Claude's
// interactive --continue picks it (its transcript was created by cli), so
// `claude -c` restores it before exec.
func TestCrossContinueAfterAPrintModeContinuation(t *testing.T) {
	s := newXStack(t)
	h := s.h
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	older, continued := continueSessions(t, s, "cli", false)
	// The user works in the folder again: its sessions are restored.
	if rep, err := sweep.Restore(ctx, s.env(), s.keys, sweep.RestoreRequest{Select: []harness.Selector{{Kind: capsule.KindClaudeSession,
		RootID: "root-acme"}}}); err != nil || rep.Count(sweep.OutRestored) != 2 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	// claude -p -c continues it: a turn appended under the same id, and the
	// -p process's SessionStart(resume) in a new ledger (the first went
	// into the capsule, S13).
	f, err := os.OpenFile(continued, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(`{"type":"user","uuid":"00000000-0000-4000-8000-0000000000f2","sessionId":"` + sid2 + `","cwd":"` + h.Root +
		`","entrypoint":"sdk-cli","message":{"role":"user","content":"go on"}}` + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(continued, mt, mt); err != nil {
		t.Fatal(err)
	}
	writeLedgerStart(t, s, sid2, "resume", "sdk-cli")
	s.clock.Advance(time.Minute)
	res := unitResult(sealAll(t, s, 1), capsule.KindClaudeSession, sweep.OutSealed)
	if gens, err := sweep.Generations(s.env(), res.Unit); err != nil || len(gens) != 2 {
		t.Fatalf("generations %+v %v", gens, err)
	}
	restoreBeforeExec(t, s, "-c")
	if !exists(continued) {
		t.Fatal("claude -c: the interactive session continued by claude -p -c was not restored before exec")
	}
	if !exists(older) {
		t.Error("claude -c: the folder's other recent session was not restored")
	}
}
