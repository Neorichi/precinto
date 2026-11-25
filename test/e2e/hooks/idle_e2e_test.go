//go:build testing

package hooks_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ui"
)

// folderStatus is the part of `precinto status --json` (schema v1, SPEC
// §16.4) this suite reads.
type folderStatus struct {
	ID           string     `json:"id"`
	State        string     `json:"state"`
	Reason       string     `json:"reason"`
	IdleDeadline *time.Time `json:"idle_deadline"`
}

// folder reads the state of root-acme from `precinto status --json`.
func (s *sandbox) folder() folderStatus {
	s.t.Helper()
	out, _ := s.run(s.home, time.Minute, nil, s.bin, "status", "--json")
	var st struct {
		Folders []folderStatus `json:"folders"`
	}
	if i := strings.Index(out, "{"); i < 0 || json.Unmarshal([]byte(out[i:]), &st) != nil {
		s.t.Fatalf("precinto status --json:\n%s", out)
	}
	for _, f := range st.Folders {
		if f.ID == "root-acme" {
			return f
		}
	}
	s.t.Fatalf("precinto status --json lists no root-acme:\n%s", out)
	return folderStatus{}
}

// seedClaudeConfig marks the throwaway CLAUDE_CONFIG_DIR as past Claude's
// first-run screens, with the protected folder trusted, so an interactive
// session accepts input at once. The keys are Claude's own and UNVERIFIED
// for the pinned version (DF-05); E2E runs settle them.
func (s *sandbox) seedClaudeConfig() {
	s.t.Helper()
	seed := map[string]any{
		"hasCompletedOnboarding": true,
		"theme":                  "dark",
		"projects": map[string]any{
			s.root: map[string]any{"hasTrustDialogAccepted": true, "hasCompletedProjectOnboarding": true},
		},
	}
	b, err := json.Marshal(seed)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.home, "claude", ".claude.json"), b, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// ticks counts the lines the loop's prompt appended to the tick file.
func ticks(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

// TestE2ESEC14IdleLoop (SEC-14; D23, D26, D37, D54): a wrapped interactive
// Claude session starts `/loop 1m …` and then nobody types. The loop's
// prompts arrive with no keystroke before them, so the daemon records them
// as automated and they never move the idle clock: the folder's idle
// deadline stays where the last keystroke put it although the session
// works every minute (busy never extends an unlock), and the folder locks
// at idle_soft. Once it is locked the loop's next prompt is blocked like a
// typed one and its tool never runs, and no unlock dialog appears.
//
// The session runs under `precinto run`, where a prompt's origin comes
// from the wrapper's keystrokes alone (D37), so whoever uses the machine
// meanwhile does not disturb it; the screen must stay unlocked (a screen
// lock would lock the folder early, reason "screen"). It needs a logged-in
// claude, PRECINTO_E2E=1 and about seven minutes: run it alone with
// `-run SEC14 -timeout 20m` when the whole suite would not fit.
func TestE2ESEC14IdleLoop(t *testing.T) {
	const (
		idleSoft = 150 * time.Second // the loop runs at 0, 60 and 120 s, then locks
		period   = 60 * time.Second
		slack    = 15 * time.Second // keystroke reports and the daemon's tick
	)
	requireE2E(t)
	if d, ok := t.Deadline(); ok && time.Until(d) < 9*time.Minute {
		t.Skip("SEC-14 needs about 7 minutes: run it alone with -run SEC14 -timeout 20m")
	}
	s := newSandbox(t, "claude")
	s.writeConfigWith(func(c *config.Config) { c.Policy.IdleSoft = config.Duration(idleSoft) })
	s.initVault()
	s.answerer(s.root, 2*time.Minute, s.bin, "unlock", "--root", s.root)
	s.seedClaudeConfig()
	tickFile := filepath.Join(s.root, "ticks.txt")

	run := s.pty(s.root, s.bin, "run", "--harness", "claude-code", "--",
		"claude", "--model", "haiku", "--plugin-dir", pluginDir(t), "--allowedTools", "Bash")
	run.expect("Claude Code", 0, 2*time.Minute)
	time.Sleep(3 * time.Second) // let the first frame settle
	run.send("/loop 1m Use the Bash tool to run exactly: date >> ticks.txt then reply with the single word OK.")
	time.Sleep(time.Second)
	run.send("\r")
	last := time.Now() // the last keystroke: from here only automated prompts arrive

	// While the folder is unlocked the loop keeps working, and its prompts
	// never push the idle deadline past the last keystroke + idle_soft.
	limit := last.Add(idleSoft + 4*slack)
	var locked folderStatus
	var lockedAt time.Time
	for {
		f := s.folder()
		if f.State == "locked" {
			locked, lockedAt = f, time.Now()
			break
		}
		if f.IdleDeadline != nil && f.IdleDeadline.After(last.Add(idleSoft+slack)) {
			t.Fatalf("an automated /loop prompt moved the idle clock: idle deadline %s, the last keystroke was at %s (idle_soft %s)",
				f.IdleDeadline.Format(time.RFC3339), last.Format(time.RFC3339), idleSoft)
		}
		if time.Now().After(limit) {
			t.Fatalf("the folder did not lock within idle_soft (%s) of the last keystroke: %+v", idleSoft, f)
		}
		time.Sleep(5 * time.Second)
	}
	if early := last.Add(idleSoft - slack); lockedAt.Before(early) || locked.Reason != string(ui.ReasonIdle) {
		t.Fatalf("locked %s after the last keystroke with reason %q, want idle after %s", lockedAt.Sub(last).Round(time.Second), locked.Reason, idleSoft)
	}
	before := ticks(t, tickFile)
	if before < 2 {
		t.Fatalf("the loop ran %d time(s) while the folder was unlocked: no automated prompt was tested", before)
	}
	run.expect(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), 0, time.Minute)

	// Locked: the loop's next prompts are blocked (a turn already running
	// when the lock came may still finish its tool), and nothing asks to
	// unlock the folder.
	time.Sleep(2*period + slack)
	if after := ticks(t, tickFile); after > before+1 {
		t.Errorf("the loop kept running tools after the lock: %d ticks at the lock, %d two periods later", before, after)
	}
	if f := s.folder(); f.State != "locked" {
		t.Errorf("the folder unlocked again without a keystroke: %+v", f)
	}
	if catalog(ui.MsgUnlockHook, ui.Vars{Harness: "\x00h", Folder: "~/work/acme"}, "\x00h").MatchString(run.text()) {
		t.Error("an automated prompt raised the hook unlock notice (D26)")
	}

	// End the session from the lock screen (Ctrl-D ends and seals it).
	run.send("\x04")
	select {
	case <-run.done:
	case <-time.After(2 * time.Minute):
		t.Errorf("precinto run did not end after Ctrl-D on the lock screen:\n%s", tail(run.text()))
	}
}
