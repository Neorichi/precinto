package hook_test

import (
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/hook"
	"github.com/Neorichi/precinto/internal/paths"
)

// TestDetectHost covers HOOKS-IO §0.7 / D56 (HOOK-2): first match wins, a
// missing marker never turns a gate into "unknown" for precinto's labels.
func TestDetectHost(t *testing.T) {
	claudePayload := []byte(`{"session_id":"00000000-0000-4000-8000-000000000001","hook_event_name":"PreToolUse"}`)
	codexTurn := []byte(`{"session_id":"00000000-0000-7000-8000-000000000001","turn_id":"00000000-0000-7000-8000-0000000000b1","hook_event_name":"UserPromptSubmit"}`)
	codexNoTurn := []byte(`{"session_id":"00000000-0000-7000-8000-000000000001","hook_event_name":"SessionStart","source":"startup"}`)
	nullTurn := []byte(`{"session_id":"x","turn_id":null}`)
	camel := []byte(`{"hook_event_name":"preToolUse"}`)
	promptMentioningTurnID := []byte(`{"session_id":"x","prompt":"what is \"turn_id\"?"}`)

	tests := []struct {
		name  string
		label string
		env   map[string]string
		raw   []byte
		want  hook.Host
	}{
		{"claude with every marker", "claude-code", map[string]string{"CLAUDE_PID": "4242", "CLAUDECODE": "1", "CLAUDE_PROJECT_DIR": "/u/work/acme"}, claudePayload, hook.HostClaude},
		{"claude without CLAUDE_PID", "claude-code", map[string]string{"CLAUDECODE": "1", "CLAUDE_PROJECT_DIR": "/u/work/acme"}, claudePayload, hook.HostClaude},
		{"claude without CLAUDE_PID and CLAUDECODE", "claude-code", map[string]string{"CLAUDE_PROJECT_DIR": "/u/work/acme"}, claudePayload, hook.HostClaude},
		{"claude with no marker: the label", "claude-code", nil, claudePayload, hook.HostClaude},
		{"claude, CLAUDECODE set but not 1: the label", "claude-code", map[string]string{"CLAUDECODE": "0"}, claudePayload, hook.HostClaude},
		{"codex with turn_id", "codex", map[string]string{"PLUGIN_ROOT": "/p"}, codexTurn, hook.HostCodex},
		{"codex SessionStart without turn_id", "codex", map[string]string{"PLUGIN_ROOT": "/p", "CLAUDE_PLUGIN_ROOT": "/p"}, codexNoTurn, hook.HostCodex},
		{"codex SessionEnd, no marker but the label", "codex", nil, codexNoTurn, hook.HostCodex},
		{"turn_id alone marks codex", "claude-code", nil, codexTurn, hook.HostCodex},
		{"null turn_id is no marker", "claude-code", nil, nullTurn, hook.HostClaude},
		{"PLUGIN_ROOT and label codex beat Claude markers", "codex", map[string]string{"PLUGIN_ROOT": "/p", "CLAUDECODE": "1"}, codexNoTurn, hook.HostCodex},
		{"PLUGIN_ROOT without Claude markers: codex", "claude-code", map[string]string{"PLUGIN_ROOT": "/p"}, claudePayload, hook.HostCodex},
		{"PLUGIN_ROOT inherited by Claude: Claude markers win", "claude-code", map[string]string{"PLUGIN_ROOT": "/p", "CLAUDECODE": "1"}, claudePayload, hook.HostClaude},
		{"a prompt mentioning turn_id is not codex", "claude-code", map[string]string{"CLAUDECODE": "1"}, promptMentioningTurnID, hook.HostClaude},
		// D92: another host's variables inherited by Claude or Codex never
		// override their markers (gates would turn observe-only).
		{"cursor version inherited by Claude", "claude-code", map[string]string{"CURSOR_VERSION": "2.0.0", "CLAUDECODE": "1"}, claudePayload, hook.HostClaude},
		{"cursor version without Claude markers", "claude-code", map[string]string{"CURSOR_VERSION": "2.0.0"}, claudePayload, hook.HostCursor},
		{"cursor plugin root", "cursor", map[string]string{"CURSOR_PLUGIN_ROOT": "/c"}, nil, hook.HostCursor},
		{"copilot variable: no marker of Copilot", "claude-code", map[string]string{"COPILOT_CLI": "1"}, claudePayload, hook.HostClaude},
		{"COPILOT_HOME inherited by Claude", "claude-code", map[string]string{"COPILOT_HOME": "/u/.copilot", "CLAUDECODE": "1"}, claudePayload, hook.HostClaude},
		{"COPILOT_HOME inherited by Codex", "codex", map[string]string{"COPILOT_HOME": "/u/.copilot", "PLUGIN_ROOT": "/p"}, codexTurn, hook.HostCodex},
		{"camelCase event name", "claude-code", nil, camel, hook.HostCopilot},
		{"droid plugin root inherited by Claude", "claude-code", map[string]string{"DROID_PLUGIN_ROOT": "/d", "CLAUDECODE": "1"}, claudePayload, hook.HostClaude},
		{"droid plugin root", "claude-code", map[string]string{"DROID_PLUGIN_ROOT": "/d"}, claudePayload, hook.HostDroid},
		{"factory project dir", "claude-code", map[string]string{"FACTORY_PROJECT_DIR": "/u/work/acme"}, claudePayload, hook.HostDroid},
		{"the codex label beats cursor variables", "codex", map[string]string{"CURSOR_VERSION": "2", "PLUGIN_ROOT": "/p"}, codexTurn, hook.HostCodex},
		{"camelCase with cursor variables", "claude-code", map[string]string{"CURSOR_VERSION": "2"}, camel, hook.HostCursor},
		{"label cursor", "cursor", nil, nil, hook.HostCursor},
		{"label copilot", "copilot", nil, nil, hook.HostCopilot},
		{"label droid", "droid", nil, nil, hook.HostDroid},
		{"unknown label, no marker", "foo-agent", nil, claudePayload, hook.HostUnknown},
		{"unknown label with Claude markers", "foo-agent", map[string]string{"CLAUDECODE": "1"}, claudePayload, hook.HostClaude},
		{"malformed payload: markers and label", "claude-code", nil, []byte("{not json"), hook.HostClaude},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hook.DetectHost(tc.label, paths.FromMap(tc.env), tc.raw); got != tc.want {
				t.Errorf("DetectHost(%q, %v) = %q, want %q", tc.label, tc.env, got, tc.want)
			}
		})
	}
}

// TestGateEventsNeverUnknownWithoutClaudePID: every gate event of the
// claude-code label stays Claude when CLAUDE_PID is missing (SEC-32).
func TestGateEventsNeverUnknownWithoutClaudePID(t *testing.T) {
	for _, ev := range []hook.Event{hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact} {
		for _, env := range []map[string]string{nil, {"CLAUDECODE": "1"}, {"CLAUDE_PROJECT_DIR": "/u/work/acme"}} {
			raw := []byte(`{"session_id":"s","hook_event_name":"` + string(ev) + `"}`)
			if got := hook.DetectHost("claude-code", paths.FromMap(env), raw); got != hook.HostClaude {
				t.Errorf("%s with %v: host %q, want claude-code", ev, env, got)
			}
			if !hook.IsGate(hook.HostClaude, ev) {
				t.Errorf("%s is not a Claude gate", ev)
			}
		}
	}
}

func TestIsGate(t *testing.T) {
	gates := map[hook.Host][]hook.Event{
		hook.HostClaude:  {hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact},
		hook.HostCodex:   {hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact},
		hook.HostDroid:   {hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact},
		hook.HostUnknown: {hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact},
		hook.HostCursor:  {hook.UserPromptSubmit, hook.PreToolUse},
		hook.HostCopilot: {hook.PreToolUse},
	}
	all := []hook.Event{hook.SessionStart, hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest,
		hook.PostToolUse, hook.PreCompact, hook.PostCompact, hook.Stop, hook.StopFailure, hook.Interrupt,
		hook.Notification, hook.CwdChanged, hook.DirectoryAdded, hook.SessionEnd, hook.Event("FileChanged")}
	for host, want := range gates {
		for _, ev := range all {
			isWant := false
			for _, w := range want {
				isWant = isWant || w == ev
			}
			if got := hook.IsGate(host, ev); got != isWant {
				t.Errorf("IsGate(%s, %s) = %v, want %v", host, ev, got, isWant)
			}
		}
	}
}

// TestTimings pins the table of HOOKS-IO §1 and checks that every deadline
// ends strictly before the harness timeout (D22).
func TestTimings(t *testing.T) {
	s := time.Second
	want := []struct {
		host                       hook.Host
		ev                         hook.Event
		timeout, deadline, unlockW time.Duration
	}{
		{hook.HostClaude, hook.UserPromptSubmit, 90 * s, 85 * s, 60 * s},
		{hook.HostClaude, hook.PreToolUse, 10 * s, 7 * s, 0},
		{hook.HostClaude, hook.PermissionRequest, 10 * s, 7 * s, 0},
		{hook.HostClaude, hook.PreCompact, 10 * s, 7 * s, 0},
		{hook.HostClaude, hook.SessionStart, 10 * s, 5 * s, 0},
		{hook.HostClaude, hook.PostToolUse, 10 * s, 5 * s, 0},
		{hook.HostClaude, hook.CwdChanged, 5 * s, 3 * s, 0},
		{hook.HostClaude, hook.DirectoryAdded, 5 * s, 3 * s, 0},
		{hook.HostClaude, hook.Stop, 0, 5 * s, 0},
		{hook.HostClaude, hook.StopFailure, 0, 5 * s, 0},
		{hook.HostClaude, hook.Notification, 0, 5 * s, 0},
		{hook.HostClaude, hook.PostCompact, 0, 5 * s, 0},
		{hook.HostClaude, hook.SessionEnd, 1500 * time.Millisecond, 1 * s, 0},
		{hook.HostCodex, hook.UserPromptSubmit, 90 * s, 85 * s, 60 * s},
		{hook.HostCodex, hook.PreToolUse, 10 * s, 7 * s, 0},
		{hook.HostCodex, hook.PermissionRequest, 10 * s, 7 * s, 0},
		{hook.HostCodex, hook.PreCompact, 10 * s, 7 * s, 0},
		{hook.HostCodex, hook.SessionStart, 10 * s, 5 * s, 0},
		{hook.HostCodex, hook.PostToolUse, 10 * s, 5 * s, 0},
		{hook.HostCodex, hook.Interrupt, 3 * s, 2 * s, 0},
		{hook.HostCodex, hook.SessionEnd, 3 * s, 2 * s, 0},
		{hook.HostCodex, hook.Stop, 0, 5 * s, 0},
		{hook.HostCodex, hook.PostCompact, 0, 5 * s, 0},
	}
	for _, w := range want {
		got := hook.Timings(w.host, w.ev)
		if got.HarnessTimeout != w.timeout || got.Deadline != w.deadline || got.UnlockWait != w.unlockW {
			t.Errorf("Timings(%s, %s) = %+v, want timeout %v deadline %v unlock %v", w.host, w.ev, got, w.timeout, w.deadline, w.unlockW)
		}
	}
	hosts := []hook.Host{hook.HostClaude, hook.HostCodex, hook.HostCursor, hook.HostCopilot, hook.HostDroid, hook.HostUnknown}
	events := []hook.Event{hook.SessionStart, hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest,
		hook.PostToolUse, hook.PreCompact, hook.PostCompact, hook.Stop, hook.StopFailure, hook.Interrupt,
		hook.Notification, hook.CwdChanged, hook.DirectoryAdded, hook.SessionEnd, hook.Event("Unknown")}
	for _, h := range hosts {
		for _, ev := range events {
			tm := hook.Timings(h, ev)
			if tm.Deadline <= 0 {
				t.Errorf("Timings(%s, %s): no deadline", h, ev)
			}
			if tm.HarnessTimeout > 0 && tm.Deadline >= tm.HarnessTimeout {
				t.Errorf("Timings(%s, %s): deadline %v not before the harness timeout %v", h, ev, tm.Deadline, tm.HarnessTimeout)
			}
			if tm.UnlockWait > 0 && (ev != hook.UserPromptSubmit || tm.UnlockWait >= tm.Deadline) {
				t.Errorf("Timings(%s, %s): unlock wait %v", h, ev, tm.UnlockWait)
			}
		}
	}
}

func TestParseEvent(t *testing.T) {
	for name, want := range map[string]hook.Event{
		"UserPromptSubmit":     hook.UserPromptSubmit,
		"beforeSubmitPrompt":   hook.UserPromptSubmit,
		"userPromptSubmitted":  hook.UserPromptSubmit,
		"preToolUse":           hook.PreToolUse,
		"beforeShellExecution": hook.PreToolUse,
		"beforeReadFile":       hook.PreToolUse,
		"preCompact":           hook.PreCompact,
		"afterFileEdit":        hook.PostToolUse,
		"SessionEnd":           hook.SessionEnd,
		"FileChanged":          hook.Event("FileChanged"),
	} {
		if got := hook.ParseEvent(name); got != want {
			t.Errorf("ParseEvent(%q) = %q, want %q", name, got, want)
		}
	}
}
