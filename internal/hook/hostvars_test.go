package hook_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
)

// lockedGate is the daemon's answer for a locked folder.
func lockedGate() *daemonSpec {
	return &daemonSpec{Gate: &ipc.GateResp{Verdict: ipc.VerdictBlock, State: "locked", RootIDs: []string{"root-acme"},
		Reason: "idle", UserMessage: "precinto: locked", ModelMessage: "precinto: locked (model)"}}
}

// blocked reports whether a hook answer blocks in the host's real format.
func blockedFor(host string, ev string, code int, out, errs string) bool {
	switch host {
	case "claude-code":
		if code != 0 || out == "" {
			return false
		}
		var v map[string]any
		if json.Unmarshal([]byte(out), &v) != nil {
			return false
		}
		switch ev {
		case "UserPromptSubmit", "PreCompact":
			return v["decision"] == "block"
		case "PreToolUse":
			hso, _ := v["hookSpecificOutput"].(map[string]any)
			return hso["permissionDecision"] == "deny"
		case "PermissionRequest":
			hso, _ := v["hookSpecificOutput"].(map[string]any)
			d, _ := hso["decision"].(map[string]any)
			return d["behavior"] == "deny"
		}
	case "codex":
		if ev == "PreCompact" {
			var v map[string]any
			return code == 0 && json.Unmarshal([]byte(out), &v) == nil && v["continue"] == false && len(v) == 2
		}
		return code == hook.ExitBlockCode2 && out == "" && strings.TrimSpace(errs) != ""
	}
	return false
}

// TestInheritedHostVariablesKeepTheGates is D92 (H1): another host's
// variables in the user's environment reach every Claude Code and Codex
// hook process (Claude: inherited env; Codex: the session snapshot); the
// gates of a locked folder still block in Claude's or Codex's format.
func TestInheritedHostVariablesKeepTheGates(t *testing.T) {
	type tc struct {
		label, ev string
		env       map[string]string
		payload   map[string]any
	}
	claudeEnv := map[string]string{"HOME": "/u", "CLAUDECODE": "1", "CLAUDE_PID": "4242", "CLAUDE_PROJECT_DIR": "/u/work/acme"}
	codexEnv := map[string]string{"HOME": "/u", "PLUGIN_ROOT": "/p", "CLAUDE_PLUGIN_ROOT": "/p", "PWD": "/u/work/acme"}
	var cases []tc
	for _, ev := range []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PreCompact"} {
		cases = append(cases, tc{"claude-code", ev, claudeEnv, map[string]any{
			"session_id": "11111111-2222-3333-4444-555555555555", "cwd": "/u/work/acme", "hook_event_name": ev,
			"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "trigger": "auto"}})
	}
	for _, ev := range []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PreCompact"} {
		cases = append(cases, tc{"codex", ev, codexEnv, map[string]any{
			"session_id": "11111111-2222-3333-4444-555555555556", "turn_id": "t1", "cwd": "/u/work/acme", "hook_event_name": ev,
			"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "trigger": "auto", "transcript_path": nil}})
	}
	for _, extra := range []map[string]string{{"COPILOT_HOME": "/u/.config/copilot"}, {"COPILOT_GITHUB_TOKEN": "x"},
		{"CURSOR_VERSION": "3.12.17"}, {"DROID_PLUGIN_ROOT": "/d"}, {"FACTORY_PROJECT_DIR": "/u/work/acme"}} {
		for _, c := range cases {
			raw, _ := json.Marshal(c.payload)
			// Baseline: no foreign variable.
			deps, _, _ := testDeps(t, lockedGate())
			code, out, errs := runMain(t, []string{c.label, c.ev}, strings.NewReader(string(raw)), c.env, hook.TestSystem{Deps: deps})
			if !blockedFor(c.label, c.ev, code, out, errs) {
				t.Fatalf("baseline %s %s does not block: exit %d out %q err %q", c.label, c.ev, code, out, errs)
			}
			env := map[string]string{}
			for k, v := range c.env {
				env[k] = v
			}
			for k, v := range extra {
				env[k] = v
			}
			deps, _, _ = testDeps(t, lockedGate())
			code, out, errs = runMain(t, []string{c.label, c.ev}, strings.NewReader(string(raw)), env, hook.TestSystem{Deps: deps})
			if !blockedFor(c.label, c.ev, code, out, errs) {
				t.Errorf("%s %s in a locked folder with %v in the environment: exit %d stdout %q stderr %q (not a block %s accepts)",
					c.label, c.ev, extra, code, out, strings.TrimSpace(errs), c.label)
			}
		}
	}
}

// TestUnicodeNormalizedCwdIsGated is D93 (H2): a folder whose name APFS
// stores in NFD is one folder in both spellings. Claude Code reports its
// cwd in NFC, Codex reports getcwd (the stored form): with the root
// recorded in either spelling, the locked folder's prompt is blocked.
func TestUnicodeNormalizedCwdIsGated(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("normalization-insensitive file system (APFS) only")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nfd, nfc := "Disen\u0303o", "Dise\u00f1o"
	if err := os.Mkdir(filepath.Join(base, nfd), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, nfc)); err != nil {
		t.Skip("this volume is normalization-sensitive")
	}
	for _, tc := range []struct {
		name, root, label, cwd string
	}{
		{"root recorded NFD, Claude reports NFC", nfd, "claude-code", nfc},
		{"root typed NFC, Codex reports the stored NFD", nfc, "codex", nfd},
	} {
		deps, _, rec := testDeps(t, lockedGate())
		deps.Cfg.Roots = []config.Root{{ID: "root-acme", Path: filepath.Join(base, tc.root), MD: config.MDLedger}}
		cwd := filepath.Join(base, tc.cwd)
		payload := map[string]any{"session_id": "11111111-2222-3333-4444-555555555557", "cwd": cwd, "hook_event_name": "UserPromptSubmit", "prompt": "x"}
		env := map[string]string{"HOME": "/u"}
		if tc.label == "codex" {
			payload["turn_id"] = "t1"
			env["PLUGIN_ROOT"] = "/p"
		} else {
			env["CLAUDECODE"] = "1"
			env["CLAUDE_PROJECT_DIR"] = cwd
		}
		raw, _ := json.Marshal(payload)
		code, out, errs := runMain(t, []string{tc.label, "UserPromptSubmit"}, strings.NewReader(string(raw)), env, hook.TestSystem{Deps: deps})
		if !blockedFor(tc.label, "UserPromptSubmit", code, out, errs) || len(rec.Calls()) == 0 {
			t.Errorf("%s: exit %d stdout %q stderr %q, %d daemon call(s): the locked folder's prompt is allowed",
				tc.name, code, out, strings.TrimSpace(errs), len(rec.Calls()))
		}
	}
}
