//go:build testing

package hooks_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// pluginDir is precinto's Claude plugin of this checkout.
func pluginDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(repoRoot, "plugin"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestE2E1SessionSealedAfterExit (E2E-1): `claude -p --plugin-dir ./plugin`
// in an unlocked protected folder passes every gate (and answers when the
// model is reachable); once it exits the session is sealed and no marker is
// left in the throwaway home outside capsules. Claude writes the transcript,
// with the marker, whether or not the model answered.
func TestE2E1SessionSealedAfterExit(t *testing.T) {
	s := newSandbox(t, "claude")
	s.initVault()
	s.answerer(s.root, 2*time.Minute, s.bin, "unlock", "--root", s.root)
	m := testkit.Marker(t)
	out, code := s.claude(s.root, pluginDir(t), "Remember the word "+m+". Reply with the single word OK.")
	r := parseClaude(out)
	if r.SessionID == "" || !passedGates(r) {
		t.Fatalf("claude -p in an unlocked folder did not get past the gates: exit %d\n%s", code, out)
	}
	if (code != 0 || r.IsError) && (s.modelReachable() || !loginError(r.Result)) {
		t.Fatalf("claude -p in an unlocked folder: exit %d\n%s", code, out)
	}
	// SessionEnd queued the seal; the detached worker seals once claude has
	// exited and the transcript is quiet.
	s.awaitSealed(m, 3*time.Minute)
	if entries, _ := os.ReadDir(filepath.Join(s.base, "capsules", "claude-code")); len(entries) == 0 {
		t.Error("no claude-code capsule was written")
	}
	t.Logf("state after the workers: %v", s.awaitIdle(2*time.Minute))
	testkit.Hygiene(t, filepath.Join(s.base, "state"))
}

// TestE2E2LockedFolder (E2E-2, SEC-17): in a locked folder the prompt is
// blocked with the C3 text, the model never sees it, and the marker reaches
// none of precinto's files; Claude still writes the blocked prompt into the
// session's transcript (SPEC §19), which is sealed once the session ended.
// Outside the folder the prompt passes every gate (and Claude answers when
// the model is reachable).
func TestE2E2LockedFolder(t *testing.T) {
	s := newSandbox(t, "claude")
	s.initVault()
	m := testkit.Marker(t)
	out, _ := s.claude(s.root, pluginDir(t), m+" Reply with the single word PINEAPPLE.")
	r := parseClaude(out)
	// C3.blocked up to its lock reason, which depends on how the folder
	// locked (catalog text, CC-38).
	locked, _, _ := strings.Cut(ui.Format(ui.MsgPromptBlocked, ui.Vars{Folder: "~/work/acme"}), " (")
	if passedGates(r) || !strings.Contains(out, locked) || strings.Contains(r.Result, "PINEAPPLE") {
		t.Errorf("prompt in the locked folder was not blocked with %q:\n%s", locked, out)
	}
	if strings.Contains(out, m) {
		t.Errorf("the blocked prompt was echoed (suppressOriginalPrompt):\n%s", out)
	}
	s.leakCheck(m)
	s.awaitSealed(m, 3*time.Minute)

	out, code := s.claude(s.outside, pluginDir(t), "Reply with the single word OK.")
	r = parseClaude(out)
	switch {
	case !passedGates(r):
		t.Errorf("outside every folder the prompt must pass precinto's gates: exit %d\n%s", code, out)
	case s.modelReachable() && (code != 0 || r.IsError || !strings.Contains(r.Result, "OK")):
		t.Errorf("outside every folder Claude must answer: exit %d\n%s", code, out)
	}
}

// replayPlugin writes a test-only plugin whose hook for event prints out
// verbatim (TESTPLAN §2: a test plugin directory with a generated shim).
func replayPlugin(t *testing.T, s *sandbox, event string, out []byte) string {
	t.Helper()
	dir := filepath.Join(s.home, "replay-"+event)
	for _, d := range []string{".claude-plugin", "hooks", "scripts"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		".claude-plugin/plugin.json": `{"name":"precinto-replay","version":"0.0.0","description":"E2E replay of one precinto hook output"}`,
		"hooks/hooks.json":           `{"hooks":{"` + event + `":[{"hooks":[{"type":"command","command":"sh \"${CLAUDE_PLUGIN_ROOT}/scripts/replay\"","timeout":10,"onFailure":"block"}]}]}}`,
		"scripts/replay":             "#!/bin/sh\ncat >/dev/null\ncat \"$(dirname \"$0\")/out.json\"\n",
		"scripts/out.json":           string(out),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestE2EReplayClaudeOutputs (HOOK-5, HA4): every Claude output precinto
// can print is replayed through a real claude -p and has its effect: the
// prompt is blocked, the tool and the permission are denied, compaction is
// blocked, and the SessionStart notice is accepted. No hook error appears.
func TestE2EReplayClaudeOutputs(t *testing.T) {
	s := newSandbox(t, "claude")
	folder := "~/work/acme"
	blockPrompt := hook.Encode(hook.HostClaude, hook.UserPromptSubmit, hook.Decision{Verdict: ipc.VerdictBlock,
		UserMessage: ui.Format(ui.MsgPromptBlocked, ui.Vars{Folder: folder, Reason: ui.ReasonManual})})
	denyTool := hook.FailClosed(hook.HostClaude, hook.PreToolUse, folder)
	denyPermission := hook.FailClosed(hook.HostClaude, hook.PermissionRequest, folder)
	blockCompact := hook.FailClosed(hook.HostClaude, hook.PreCompact, folder)
	startNotice := hook.FailClosed(hook.HostClaude, hook.SessionStart, folder)
	noHookError := func(name, out string) {
		t.Helper()
		for _, bad := range []string{"hook error", "JSON validation failed", "Failed to parse", "invalid hook output"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: the output was not accepted (%q):\n%s", name, bad, out)
			}
		}
	}

	out, _ := s.claude(s.outside, replayPlugin(t, s, "UserPromptSubmit", blockPrompt.Stdout), "Reply with the single word PINEAPPLE.")
	if r := parseClaude(out); passedGates(r) || strings.Contains(r.Result, "PINEAPPLE") || !strings.Contains(out, "is locked") {
		t.Errorf("UserPromptSubmit block not honoured:\n%s", out)
	}
	noHookError("UserPromptSubmit", out)

	// The tool and permission replays need the model to ask for a tool.
	if s.modelReachable() {
		marker := filepath.Join(s.outside, "tool-ran")
		out, _ = s.claude(s.outside, replayPlugin(t, s, "PreToolUse", denyTool.Stdout),
			"Use the Bash tool to run exactly this command: touch "+marker, "--allowedTools", "Bash")
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("PreToolUse deny not honoured: the tool ran\n%s", out)
		}
		noHookError("PreToolUse", out)

		marker = filepath.Join(s.outside, "permission-granted")
		out, _ = s.claude(s.outside, replayPlugin(t, s, "PermissionRequest", denyPermission.Stdout),
			"Use the Bash tool to run exactly this command: touch "+marker, "--permission-mode", "default")
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("PermissionRequest deny not honoured\n%s", out)
		}
		noHookError("PermissionRequest", out)
	} else {
		t.Log("PreToolUse and PermissionRequest replays skipped: no model to ask for a tool")
	}

	first, _ := s.claude(s.outside, pluginDir(t), "Reply with the single word OK.")
	if sid := parseClaude(first).SessionID; sid != "" {
		out, _ = s.claude(s.outside, replayPlugin(t, s, "PreCompact", blockCompact.Stdout), "/compact", "--resume", sid)
		switch {
		case strings.Contains(out, "compaction is paused"):
		case !s.modelReachable():
			t.Logf("PreCompact replay inconclusive without a model (a session with no answer may not compact):\n%s", tail(out))
		default:
			t.Errorf("PreCompact block not honoured:\n%s", out)
		}
		noHookError("PreCompact", out)
	} else {
		t.Errorf("no session to compact:\n%s", first)
	}

	out, code := s.claude(s.outside, replayPlugin(t, s, "SessionStart", startNotice.Stdout), "Reply with the single word OK.")
	if r := parseClaude(out); code != 0 && (s.modelReachable() || !passedGates(r) || !loginError(r.Result)) {
		t.Errorf("SessionStart notice broke the session: exit %d\n%s", code, out)
	}
	noHookError("SessionStart", out)
}

// TestE2ESEC13FailClosed (SEC-13, D56): with the binary removed, or killed
// by SIGKILL, a prompt inside a protected folder is blocked by the shim's
// static D.shim text and the model never answers; outside every folder the
// same failure lets Claude answer.
func TestE2ESEC13FailClosed(t *testing.T) {
	s := newSandbox(t, "claude")
	link := filepath.Join(s.base, "bin", "precinto")
	shim := ui.Format(ui.MsgShimFailed, ui.Vars{})
	for _, variant := range []string{"removed", "killed"} {
		_ = os.Remove(link)
		if variant == "killed" {
			if err := os.WriteFile(link, []byte("#!/bin/sh\nkill -KILL $$\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		m := testkit.Marker(t)
		out, _ := s.claude(s.root, pluginDir(t), m+" Reply with the single word PINEAPPLE.")
		if r := parseClaude(out); passedGates(r) || !strings.Contains(out, shim) || strings.Contains(r.Result, "PINEAPPLE") {
			t.Errorf("%s binary inside the folder: not blocked with D.shim:\n%s", variant, out)
		}
		out, code := s.claude(s.outside, pluginDir(t), "Reply with the single word OK.")
		switch r := parseClaude(out); {
		case !passedGates(r):
			t.Errorf("%s binary outside every folder: the prompt must pass the shim: exit %d\n%s", variant, code, out)
		case s.modelReachable() && (code != 0 || !strings.Contains(r.Result, "OK")):
			t.Errorf("%s binary outside every folder: Claude must answer: exit %d\n%s", variant, code, out)
		}
		s.leakCheck(m)
	}
}

// TestE2E8HookUnlockDialog (E2E-8, D60) needs a person at the keyboard: a
// human prompt in a locked folder raises the unlock dialog; approving it
// lets the prompt through. Run with PRECINTO_E2E=1 PRECINTO_E2E_DIALOG=1
// and approve the dialog (pinentry for the passphrase factor) when it
// appears; it passes the gate for flipping unlock_on_prompt (D60).
func TestE2E8HookUnlockDialog(t *testing.T) {
	requireE2E(t)
	if os.Getenv("PRECINTO_E2E_DIALOG") != "1" {
		t.Skip("interactive: set PRECINTO_E2E_DIALOG=1 and approve the dialog when it appears")
	}
	s := newSandbox(t, "claude")
	s.initVault()
	cfgPath := filepath.Join(s.base, "config.toml")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// unlock_on_prompt = true relaxes the policy (D48): it applies once a
	// terminal unlock confirms it, so unlock (the answerer accepts the
	// pending change listed after C13.policy), then lock again before the
	// dialog test.
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(string(b), "unlock_on_prompt = false", "unlock_on_prompt = true", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	s.answer(answerOptions{acceptPolicy: true}, s.root, 2*time.Minute, s.bin, "unlock", "--root", s.root)
	if out, code := s.run(s.home, time.Minute, nil, s.bin, "lock"); code != 0 {
		t.Fatalf("precinto lock: %d\n%s", code, out)
	}
	t.Log("approve the precinto unlock dialog now")
	out, code := s.claude(s.root, pluginDir(t), "Reply with the single word OK.")
	if r := parseClaude(out); code != 0 || !strings.Contains(r.Result, "OK") {
		t.Errorf("approved hook unlock: the prompt did not proceed: exit %d\n%s", code, out)
	}
}
