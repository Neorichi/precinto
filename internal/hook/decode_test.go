package hook_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/testkit"
)

const (
	sidC = "00000000-0000-4000-8000-000000000001"
	sidX = "00000000-0000-7000-8000-000000000001"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecodeKeepsNoContent: prompts, file content, tool output, summaries
// and assistant text never survive decoding (S11, S13).
func TestDecodeKeepsNoContent(t *testing.T) {
	m := testkit.Marker(t)
	payloads := map[hook.Event]map[string]any{
		hook.UserPromptSubmit: {"session_id": sidC, "cwd": "/u/work/acme", "prompt": m},
		hook.PreToolUse: {"session_id": sidC, "cwd": "/u/work/acme", "tool_name": "Write",
			"tool_input": map[string]any{"file_path": "/u/work/acme/a.md", "content": m, "old_string": m, "new_string": m}},
		hook.PostToolUse: {"session_id": sidC, "cwd": "/u/work/acme", "tool_name": "Edit",
			"tool_input": map[string]any{"file_path": "/u/work/acme/a.md", "old_string": m, "new_string": m}, "tool_response": map[string]any{"content": m}},
		hook.PostCompact:  {"session_id": sidC, "cwd": "/u/work/acme", "compact_summary": m},
		hook.PreCompact:   {"session_id": sidC, "cwd": "/u/work/acme", "custom_instructions": m, "trigger": "manual"},
		hook.Stop:         {"session_id": sidC, "cwd": "/u/work/acme", "last_assistant_message": m},
		hook.Notification: {"session_id": sidC, "cwd": "/u/work/acme", "message": m, "notification_type": "idle_prompt"},
	}
	env := paths.FromMap(map[string]string{"HOME": "/u", "CLAUDE_PID": "4242", "SECRET_TOKEN": m})
	for ev, p := range payloads {
		got, err := hook.Decode(hook.HostClaude, "claude-code", ev, mustJSON(t, p), env, fakeplatform.NewProcs())
		if err != nil {
			t.Fatalf("%s: %v", ev, err)
		}
		if s := fmt.Sprintf("%#v", got); strings.Contains(s, m) {
			t.Errorf("%s: the decoded payload retains content: %s", ev, s)
		}
	}
	// Malformed JSON around a marker: the error carries no payload byte.
	_, err := hook.Decode(hook.HostClaude, "claude-code", hook.UserPromptSubmit, []byte(`{"prompt":"`+m+`", oops}`), env, nil)
	if err == nil || strings.Contains(err.Error(), m) || strings.Contains(err.Error(), "oops") {
		t.Errorf("malformed payload error %v", err)
	}
}

func TestDecodeClaude(t *testing.T) {
	procs := fakeplatform.NewProcs()
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 77}, PPID: 1, Exe: "/u/.local/share/claude/versions/2.1.329"})
	raw := mustJSON(t, map[string]any{
		"session_id":      sidC,
		"prompt_id":       "00000000-0000-4000-8000-0000000000a1",
		"transcript_path": "/u/.claude/projects/-u-work-acme/" + sidC + ".jsonl",
		"cwd":             "/u/work/acme/sub/../src",
		"scratchpad_dir":  "/tmp/claude-501/-u-work-acme/" + sidC + "/scratchpad",
		"agent_id":        "agent-1",
		"tool_name":       "MultiEdit",
		"tool_input":      map[string]any{"file_path": "notes/a.MD", "edits": []any{}},
	})
	env := paths.FromMap(map[string]string{
		"HOME": "/u", "CLAUDE_PID": "4242", "CLAUDE_PROJECT_DIR": "/u/work/acme",
		"CLAUDE_CODE_ENTRYPOINT": "cli", "CLAUDE_CODE_EXECPATH": "/u/.local/share/claude/versions/2.1.329",
	})
	p, err := hook.Decode(hook.HostClaude, "claude-code", hook.PostToolUse, raw, env, procs)
	if err != nil {
		t.Fatal(err)
	}
	want := hook.Payload{
		Host: hook.HostClaude, Label: "claude-code", Event: hook.PostToolUse,
		SID: sidC, PromptID: "00000000-0000-4000-8000-0000000000a1",
		TranscriptPath: "/u/.claude/projects/-u-work-acme/" + sidC + ".jsonl",
		Cwd:            "/u/work/acme/src", ProjectDir: "/u/work/acme", ConfigDir: "/u/.claude",
		ScratchpadDir: "/tmp/claude-501/-u-work-acme/" + sidC + "/scratchpad",
		ToolName:      "MultiEdit",
		Paths:         []string{"/u/work/acme/src/notes/a.MD"}, MarkdownPaths: []string{"/u/work/acme/src/notes/a.MD"},
		HarnessPID: 4242, HarnessProc: platform.ProcID{PID: 4242, StartUS: 77},
		HarnessVersion: "2.1.329", Entrypoint: "cli", AgentID: "agent-1",
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("Decode =\n%#v\nwant\n%#v", p, want)
	}
}

func TestDecodeEvents(t *testing.T) {
	env := paths.FromMap(map[string]string{"HOME": "/u", "CLAUDE_CONFIG_DIR": "/u/cfg"})
	cases := []struct {
		ev   hook.Event
		raw  map[string]any
		pick func(hook.Payload) any
		want any
	}{
		{hook.SessionStart, map[string]any{"session_id": "s", "cwd": "/u", "source": "resume"}, func(p hook.Payload) any { return p.Source }, "resume"},
		{hook.SessionEnd, map[string]any{"session_id": "s", "cwd": "/u", "reason": "clear"}, func(p hook.Payload) any { return p.Reason }, "clear"},
		{hook.PreCompact, map[string]any{"session_id": "s", "cwd": "/u", "trigger": "auto"}, func(p hook.Payload) any { return p.Trigger }, "auto"},
		{hook.Notification, map[string]any{"session_id": "s", "cwd": "/u", "notification_type": "idle_prompt"}, func(p hook.Payload) any { return p.Notification }, "idle_prompt"},
		{hook.CwdChanged, map[string]any{"session_id": "s", "cwd": "/u/b", "old_cwd": "/u/a", "new_cwd": "/u/b"}, func(p hook.Payload) any { return [2]string{p.OldCwd, p.NewCwd} }, [2]string{"/u/a", "/u/b"}},
		{hook.DirectoryAdded, map[string]any{"session_id": "s", "cwd": "/u", "directory": "/u/work/acme", "source": "slash_command"}, func(p hook.Payload) any { return p.AddedDirs }, []string{"/u/work/acme"}},
		// No transcript: CLAUDE_CONFIG_DIR is the config dir.
		{hook.Stop, map[string]any{"session_id": "s", "cwd": "/u"}, func(p hook.Payload) any { return p.ConfigDir }, "/u/cfg"},
		// Relative cwd and paths are never trusted.
		{hook.PreToolUse, map[string]any{"session_id": "s", "cwd": "rel", "tool_name": "Read", "tool_input": map[string]any{"file_path": "x"}}, func(p hook.Payload) any { return [2]any{p.Cwd, p.Paths} }, [2]any{"", []string(nil)}},
		// Non-string path values and non-object tool_input are skipped.
		{hook.PreToolUse, map[string]any{"session_id": "s", "cwd": "/u", "tool_name": "X", "tool_input": map[string]any{"path": 7, "file_path": "/u/f"}}, func(p hook.Payload) any { return p.Paths }, []string{"/u/f"}},
		{hook.PreToolUse, map[string]any{"session_id": "s", "cwd": "/u", "tool_name": "X", "tool_input": "string"}, func(p hook.Payload) any { return p.Paths }, []string(nil)},
		// Markdown only for writing tools.
		{hook.PostToolUse, map[string]any{"session_id": "s", "cwd": "/u", "tool_name": "Read", "tool_input": map[string]any{"file_path": "/u/a.md"}}, func(p hook.Payload) any { return p.MarkdownPaths }, []string(nil)},
		{hook.PostToolUse, map[string]any{"session_id": "s", "cwd": "/u", "tool_name": "NotebookEdit", "tool_input": map[string]any{"notebook_path": "/u/a.markdown"}}, func(p hook.Payload) any { return p.MarkdownPaths }, []string{"/u/a.markdown"}},
		{hook.PostToolUse, map[string]any{"session_id": "s", "cwd": "/u", "tool_name": "Write", "tool_input": map[string]any{"file_path": "/u/a.mdx.txt"}}, func(p hook.Payload) any { return p.MarkdownPaths }, []string(nil)},
	}
	for i, c := range cases {
		p, err := hook.Decode(hook.HostClaude, "claude-code", c.ev, mustJSON(t, c.raw), env, nil)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got := c.pick(p); !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d (%s): got %#v, want %#v", i, c.ev, got, c.want)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	env := paths.FromMap(map[string]string{"HOME": "/u"})
	for name, raw := range map[string]string{
		"empty":       "",
		"spaces":      "  \n",
		"array":       `[{"session_id":"s"}]`,
		"string":      `"x"`,
		"truncated":   `{"session_id":"s"`,
		"wrong type":  `{"session_id":"s","cwd":7}`,
		"wrong roots": `{"workspace_roots":"x"}`,
	} {
		if _, err := hook.Decode(hook.HostClaude, "claude-code", hook.PreToolUse, []byte(raw), env, nil); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Codex null transcript_path (ephemeral sessions) is fine.
	if _, err := hook.Decode(hook.HostCodex, "codex", hook.UserPromptSubmit, []byte(`{"session_id":"s","transcript_path":null,"cwd":"/u","turn_id":"t"}`), env, nil); err != nil {
		t.Errorf("null transcript_path: %v", err)
	}
}

func TestDecodeOversized(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 64 MiB")
	}
	raw := make([]byte, hook.MaxPayload+1)
	_, err := hook.Decode(hook.HostClaude, "claude-code", hook.UserPromptSubmit, raw, paths.FromMap(nil), nil)
	if err == nil {
		t.Fatal("oversized payload decoded")
	}
}

// TestDecodeCodexAncestry: the harness pid is the nearest ancestor whose
// executable is codex, through fish, bash or a compound sh command
// (LIVE-10, HA17).
func TestDecodeCodexAncestry(t *testing.T) {
	for _, chain := range [][]string{
		{"/opt/homebrew/bin/fish", "/bin/sh"},
		{"/bin/bash", "/bin/sh"},
		{"/bin/zsh", "/bin/sh", "/bin/sh"}, // `sh -c 'a && sh shim'`
		{"/bin/sh"},
	} {
		procs := fakeplatform.NewProcs()
		procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 7000, StartUS: 70}, PPID: 1, Exe: "/u/.npm/lib/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex"})
		parent := 7000
		pid := 8000
		for _, exe := range chain {
			procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: int64(pid)}, PPID: parent, Exe: exe})
			parent, pid = pid, pid+1
		}
		procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 9000, StartUS: 90}, PPID: parent, Exe: "/u/bin/precinto"})
		restore := hook.SetSelfPID(9000, parent)
		p, err := hook.Decode(hook.HostCodex, "codex", hook.UserPromptSubmit,
			[]byte(`{"session_id":"`+sidX+`","turn_id":"t","cwd":"/u/work/acme"}`),
			paths.FromMap(map[string]string{"HOME": "/u", "CODEX_HOME": "/u/h"}), procs)
		restore()
		if err != nil {
			t.Fatal(err)
		}
		if p.HarnessPID != 7000 || p.HarnessProc != (platform.ProcID{PID: 7000, StartUS: 70}) {
			t.Errorf("chain %v: harness %d %+v, want codex 7000", chain, p.HarnessPID, p.HarnessProc)
		}
		if p.CodexHome != "/u/h" || p.ConfigDir != "/u/h" {
			t.Errorf("chain %v: codex home %q config %q", chain, p.CodexHome, p.ConfigDir)
		}
	}
	// No codex ancestor (or an unreadable table): no pid rather than a guess.
	procs := fakeplatform.NewProcs()
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 9000, StartUS: 90}, PPID: 8000, Exe: "/u/bin/precinto"})
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 8000, StartUS: 80}, PPID: 1, Exe: "/bin/sh"})
	restore := hook.SetSelfPID(9000, 8000)
	defer restore()
	p, err := hook.Decode(hook.HostCodex, "codex", hook.SessionEnd, []byte(`{"session_id":"s","cwd":"/u"}`), paths.FromMap(map[string]string{"HOME": "/u"}), procs)
	if err != nil || p.HarnessPID != 0 || p.ConfigDir != "/u/.codex" {
		t.Errorf("no codex ancestor: %+v %v", p, err)
	}
	procs.SetErr(fakeplatform.OpLookup, errors.New("unreadable"))
	if p, _ := hook.Decode(hook.HostCodex, "codex", hook.SessionEnd, []byte(`{"session_id":"s","cwd":"/u"}`), paths.FromMap(nil), procs); p.HarnessPID != 0 {
		t.Errorf("unreadable table: pid %d", p.HarnessPID)
	}
}

// TestDecodeClaudeAncestry: without CLAUDE_PID the harness is the nearest
// non-shell ancestor (HOOKS-IO §0.7: CLAUDE_PID is missing on some events).
func TestDecodeClaudeAncestry(t *testing.T) {
	procs := fakeplatform.NewProcs()
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 42}, PPID: 1, Exe: "/u/.local/share/claude/versions/2.1.329"})
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 8001, StartUS: 81}, PPID: 4242, Exe: "/bin/sh"})
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 8002, StartUS: 82}, PPID: 8001, Exe: "/bin/dash"})
	procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 9000, StartUS: 90}, PPID: 8002, Exe: "/u/bin/precinto"})
	restore := hook.SetSelfPID(9000, 8002)
	defer restore()
	p, err := hook.Decode(hook.HostClaude, "claude-code", hook.PreCompact, []byte(`{"session_id":"s","cwd":"/u"}`), paths.FromMap(map[string]string{"HOME": "/u"}), procs)
	if err != nil || p.HarnessPID != 4242 || p.HarnessProc.StartUS != 42 {
		t.Errorf("ancestry: %+v %v", p, err)
	}
	// A malformed CLAUDE_PID is ignored; an unreadable table falls back to
	// the parent pid.
	procs.SetErr(fakeplatform.OpLookup, errors.New("unreadable"))
	p, _ = hook.Decode(hook.HostClaude, "claude-code", hook.PreCompact, []byte(`{"session_id":"s","cwd":"/u"}`), paths.FromMap(map[string]string{"CLAUDE_PID": "abc"}), procs)
	if p.HarnessPID != 8002 || !p.HarnessProc.IsZero() {
		t.Errorf("fallback: %d %+v", p.HarnessPID, p.HarnessProc)
	}
}

func TestDecodeApplyPatch(t *testing.T) {
	restore := hook.SetApplyPatchPaths(fakeApplyPatchPaths)
	defer restore()
	patch := "*** Begin Patch\n*** Add File: docs/new.md\n+x\n*** Update File: /u/work/acme/old.go\n*** Move to: docs/moved.markdown\n*** End Patch\n"
	raw := mustJSON(t, map[string]any{"session_id": sidX, "turn_id": "t", "cwd": "/u/work/acme", "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}})
	p, err := hook.Decode(hook.HostCodex, "codex", hook.PostToolUse, raw, paths.FromMap(map[string]string{"HOME": "/u"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/u/work/acme/docs/new.md", "/u/work/acme/old.go", "/u/work/acme/docs/moved.markdown"}
	if !reflect.DeepEqual(p.Paths, wantPaths) {
		t.Errorf("paths %v, want %v", p.Paths, wantPaths)
	}
	if want := []string{"/u/work/acme/docs/new.md", "/u/work/acme/docs/moved.markdown"}; !reflect.DeepEqual(p.MarkdownPaths, want) {
		t.Errorf("markdown %v, want %v", p.MarkdownPaths, want)
	}
	// A failing extractor loses the paths, never the decision.
	hook.SetApplyPatchPaths(func([]byte, string) []string { panic("boom") })
	if p, err := hook.Decode(hook.HostCodex, "codex", hook.PreToolUse, raw, paths.FromMap(nil), nil); err != nil || len(p.Paths) != 0 || p.Cwd != "/u/work/acme" {
		t.Errorf("panicking extractor: %+v %v", p, err)
	}
}

func TestDecodeExperimental(t *testing.T) {
	// Cursor: conversation id, workspace roots taint, file_path.
	raw := mustJSON(t, map[string]any{"conversation_id": "c1", "hook_event_name": "afterFileEdit", "workspace_roots": []string{"/u/work/acme", "/u/other"}, "file_path": "/u/work/acme/n.md"})
	p, err := hook.Decode(hook.HostCursor, "cursor", hook.PostToolUse, raw, paths.FromMap(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.SID != "c1" || p.Cwd != "/u/work/acme" || !reflect.DeepEqual(p.AddedDirs, []string{"/u/work/acme", "/u/other"}) ||
		!reflect.DeepEqual(p.Paths, []string{"/u/work/acme/n.md"}) || !reflect.DeepEqual(p.MarkdownPaths, []string{"/u/work/acme/n.md"}) {
		t.Errorf("cursor: %+v", p)
	}
	// Copilot: camelCase keys, toolArgs as a JSON string.
	raw = mustJSON(t, map[string]any{"timestamp": 1, "cwd": "/u/work/acme", "toolName": "edit", "toolArgs": `{"path":"notes/x.md","content":"c"}`})
	p, err = hook.Decode(hook.HostCopilot, "copilot", hook.PreToolUse, raw, paths.FromMap(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "edit" || !reflect.DeepEqual(p.Paths, []string{"/u/work/acme/notes/x.md"}) {
		t.Errorf("copilot: %+v", p)
	}
}
